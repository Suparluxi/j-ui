package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/secure"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrLoginLimited       = errors.New("too many login attempts")
)

type Service struct {
	store  *database.Store
	ttl    time.Duration
	auth   sync.RWMutex
	mu     sync.Mutex
	fails  map[string][]time.Time
	busy   map[string]int
	sweeps uint64
	active int
}

const (
	failureWindow     = 15 * time.Minute
	maxFailureSources = 4096
	maxActiveLogins   = 4
	sweepInterval     = 64
)

func NewService(store *database.Store, ttl time.Duration) *Service {
	return &Service{
		store: store,
		ttl:   ttl,
		fails: make(map[string][]time.Time),
		busy:  make(map[string]int),
	}
}

func (s *Service) Login(ctx context.Context, username, password, sourceIP string) (string, model.Session, error) {
	if !s.reserveAttempt(sourceIP) {
		return "", model.Session{}, ErrLoginLimited
	}
	outcome := 0
	defer func() { s.finishAttempt(sourceIP, outcome) }()
	s.auth.RLock()
	defer s.auth.RUnlock()
	hash, err := s.store.PasswordHash(ctx, username)
	if err != nil || !VerifyPassword(hash, password) {
		outcome = 1
		return "", model.Session{}, ErrInvalidCredentials
	}

	token, err := secure.RandomToken(32)
	if err != nil {
		return "", model.Session{}, err
	}
	csrf, err := secure.RandomToken(24)
	if err != nil {
		return "", model.Session{}, err
	}
	session := model.Session{
		TokenHash: secure.HashToken(token),
		CSRFToken: csrf,
		ExpiresAt: time.Now().Add(s.ttl).UTC(),
	}
	if err := s.store.CreateSession(ctx, session, sourceIP); err != nil {
		return "", model.Session{}, err
	}
	outcome = 2
	return token, session, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (model.Session, error) {
	if token == "" {
		return model.Session{}, ErrInvalidCredentials
	}
	return s.store.Session(ctx, secure.HashToken(token))
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.store.DeleteSession(ctx, secure.HashToken(token))
}

func (s *Service) ChangePassword(ctx context.Context, current, replacement string) error {
	s.auth.Lock()
	defer s.auth.Unlock()
	username, err := s.store.AdministratorUsername(ctx)
	if err != nil {
		return ErrInvalidCredentials
	}
	hash, err := s.store.PasswordHash(ctx, username)
	if err != nil || !VerifyPassword(hash, current) {
		return ErrInvalidCredentials
	}
	newHash, err := HashPassword(replacement)
	if err != nil {
		return err
	}
	return s.store.ChangePassword(ctx, newHash)
}

func (s *Service) Limited(sourceIP string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	recent := s.prune(sourceIP, now)
	return len(recent)+s.busy[sourceIP] >= 5
}

func (s *Service) reserveAttempt(sourceIP string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sweeps++
	if s.sweeps%sweepInterval == 0 || len(s.fails) >= maxFailureSources {
		s.pruneAll(now)
	}
	recent := s.prune(sourceIP, now)
	if len(recent)+s.busy[sourceIP] >= 5 || s.active >= maxActiveLogins {
		return false
	}
	_, knownFailure := s.fails[sourceIP]
	_, knownBusy := s.busy[sourceIP]
	if !knownFailure && !knownBusy &&
		len(s.fails)+len(s.busy) >= maxFailureSources {
		return false
	}
	s.busy[sourceIP]++
	s.active++
	return true
}

func (s *Service) finishAttempt(sourceIP string, outcome int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy[sourceIP] > 1 {
		s.busy[sourceIP]--
	} else {
		delete(s.busy, sourceIP)
	}
	if s.active > 0 {
		s.active--
	}
	switch outcome {
	case 1:
		now := time.Now()
		recent := s.prune(sourceIP, now)
		if len(recent) != 0 || len(s.fails) < maxFailureSources {
			s.fails[sourceIP] = append(recent, now)
		}
	case 2:
		delete(s.fails, sourceIP)
	}
}

func (s *Service) prune(sourceIP string, now time.Time) []time.Time {
	cutoff := now.Add(-failureWindow)
	recent := s.fails[sourceIP][:0]
	for _, attempt := range s.fails[sourceIP] {
		if attempt.After(cutoff) {
			recent = append(recent, attempt)
		}
	}
	if len(recent) == 0 {
		delete(s.fails, sourceIP)
	} else {
		s.fails[sourceIP] = recent
	}
	return recent
}

func (s *Service) pruneAll(now time.Time) {
	for sourceIP := range s.fails {
		s.prune(sourceIP, now)
	}
}
