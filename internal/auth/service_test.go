package auth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/secure"
)

func TestConcurrentAttemptsAreReservedAtomically(t *testing.T) {
	service := &Service{
		ttl: time.Hour, fails: make(map[string][]time.Time), busy: make(map[string]int),
	}
	const workers = 20
	start := make(chan struct{})
	release := make(chan struct{})
	var allowed atomic.Int32
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if !service.reserveAttempt("192.0.2.1") {
				return
			}
			allowed.Add(1)
			<-release
			service.finishAttempt("192.0.2.1", 1)
		}()
	}
	close(start)
	for attempt := 0; attempt < 100 && allowed.Load() < 5; attempt++ {
		time.Sleep(time.Millisecond)
	}
	close(release)
	group.Wait()
	if allowed.Load() != maxActiveLogins {
		t.Fatalf("allowed attempts = %d, want global cap %d", allowed.Load(), maxActiveLogins)
	}
	if !service.reserveAttempt("192.0.2.1") {
		t.Fatal("fifth source attempt was not admitted after active hashes completed")
	}
	service.finishAttempt("192.0.2.1", 1)
	if !service.Limited("192.0.2.1") {
		t.Fatal("source was not limited after five concurrent failures")
	}
}

func TestConcurrentPasswordChangeCannotLeaveOldPasswordSession(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	oldPassword := "old-password-123"
	hash, err := HashPassword(oldPassword)
	if err != nil {
		t.Fatal(err)
	}
	subscriptionToken := "subscription-token-with-sufficient-length"
	tokenEncrypted, err := sealer.Seal([]byte(subscriptionToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bootstrap(context.Background(), database.Bootstrap{
		AdminPasswordHash: hash, AdminPath: "manage-00112233445566778899aabb",
		TokenHash: secure.HashToken(subscriptionToken), TokenEncrypted: tokenEncrypted,
	}); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, time.Hour)
	start := make(chan struct{})
	var token string
	var loginErr, changeErr error
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		<-start
		token, _, loginErr = service.Login(context.Background(), "admin", oldPassword, "192.0.2.2")
	}()
	go func() {
		defer group.Done()
		<-start
		changeErr = service.ChangePassword(context.Background(), oldPassword, "new-password-123")
	}()
	close(start)
	group.Wait()
	if changeErr != nil {
		t.Fatalf("ChangePassword: %v", changeErr)
	}
	if loginErr == nil {
		if _, err := service.Authenticate(context.Background(), token); err == nil {
			t.Fatal("old-password login left a valid session after concurrent password change")
		}
	} else if !errors.Is(loginErr, ErrInvalidCredentials) {
		t.Fatalf("Login: %v", loginErr)
	}
}

func TestFailureSourcesArePrunedAndBounded(t *testing.T) {
	service := &Service{
		ttl: time.Hour, fails: make(map[string][]time.Time), busy: make(map[string]int),
	}
	expired := time.Now().Add(-failureWindow - time.Minute)
	service.fails["expired"] = []time.Time{expired}
	if service.Limited("expired") {
		t.Fatal("expired source was limited")
	}
	if _, found := service.fails["expired"]; found {
		t.Fatal("empty expired source was retained")
	}
	now := time.Now()
	for index := 0; index < maxFailureSources; index++ {
		service.fails[fmt.Sprintf("192.0.2.%d", index)] = []time.Time{now}
	}
	if service.reserveAttempt("198.51.100.1") {
		t.Fatal("new source was admitted after the bounded source table filled")
	}
	if len(service.fails) > maxFailureSources {
		t.Fatalf("failure source count = %d", len(service.fails))
	}
}

func TestUniqueConcurrentSourcesCannotOverflowFailureTable(t *testing.T) {
	service := &Service{
		ttl: time.Hour, fails: make(map[string][]time.Time), busy: make(map[string]int),
	}
	var admitted []string
	for index := 0; index < maxFailureSources*2; index++ {
		source := fmt.Sprintf("2001:db8::%x", index)
		if service.reserveAttempt(source) {
			admitted = append(admitted, source)
		}
	}
	if len(admitted) != maxActiveLogins {
		t.Fatalf("active unique logins = %d, want %d", len(admitted), maxActiveLogins)
	}
	for _, source := range admitted {
		service.finishAttempt(source, 1)
	}
	if len(service.fails) > maxFailureSources || len(service.busy) != 0 || service.active != 0 {
		t.Fatalf("fails=%d busy=%d active=%d", len(service.fails), len(service.busy), service.active)
	}
}
