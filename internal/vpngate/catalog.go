package vpngate

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

const DefaultAPIURL = "https://www.vpngate.net/api/iphone/"
const DefaultMirrorListURL = "https://www.vpngate.net/en/sites.aspx"

const (
	primaryFetchTimeout    = 15 * time.Second
	mirrorFetchTimeout     = 30 * time.Second
	mirrorDiscoveryTimeout = 8 * time.Second
	candidateProbeTimeout  = 3 * time.Second
	catalogProbeTimeout    = 15 * time.Second
)

// OfficialMirrorAPIURLs bootstrap the fallback list when official directory
// discovery fails. Fetch always tries the primary before these mirrors.
var OfficialMirrorAPIURLs = []string{
	"http://62.133.35.246:2265/api/iphone/",
	"http://150.40.105.16:33958/api/iphone/",
	"http://150.40.105.3:24869/api/iphone/",
	"http://150.40.105.9:26500/api/iphone/",
}

type Fetcher struct {
	mu            sync.RWMutex
	URL           string
	MirrorURLs    []string
	MirrorListURL string
	Client        *http.Client
	Probe         func(context.Context, model.VPNGateCandidate) error
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		URL:           DefaultAPIURL,
		MirrorURLs:    append([]string(nil), OfficialMirrorAPIURLs...),
		MirrorListURL: DefaultMirrorListURL,
		Client:        &http.Client{Timeout: mirrorFetchTimeout, CheckRedirect: catalogRedirect},
		Probe:         probeCandidate,
	}
}

func catalogRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many VPNGate redirects")
	}
	origin := via[0].URL
	if request.URL.User != nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") {
		return errors.New("unsafe VPNGate redirect")
	}
	// An HTTP volunteer mirror cannot redirect probes into local services or
	// another host. The trusted HTTPS official directory must stay on its host.
	if request.URL.Host != origin.Host || (origin.Scheme == "https" && request.URL.Scheme != "https") {
		return errors.New("cross-host or downgrade VPNGate redirect rejected")
	}
	return nil
}

// RefreshMirrors discovers addresses from the official directory. Failed
// discovery preserves the last known list; catalogs are still fetched primary-first.
func (f *Fetcher) RefreshMirrors(ctx context.Context) error {
	probeCtx, cancel := context.WithTimeout(ctx, mirrorDiscoveryTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, f.MirrorListURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "J-UI/0.2 (+https://github.com/Suparluxi/j-ui)")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := f.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("mirror directory HTTP %d", response.StatusCode)
	}
	mirrors, err := parseMirrorList(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.MirrorURLs = mirrors
	f.mu.Unlock()
	log.Printf("VPNGate mirror directory refreshed: %d endpoints", len(mirrors))
	return nil
}

func parseMirrorList(reader io.Reader) ([]string, error) {
	parser := xml.NewDecoder(reader)
	parser.Strict = false
	parser.AutoClose = xml.HTMLAutoClose
	parser.Entity = xml.HTMLEntity
	var mirrors []string
	seen := make(map[string]bool)
	for {
		token, err := parser.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse mirror directory: %w", err)
		}
		element, ok := token.(xml.StartElement)
		if !ok || !strings.EqualFold(element.Name.Local, "a") {
			continue
		}
		for _, attr := range element.Attr {
			if !strings.EqualFold(attr.Name.Local, "href") {
				continue
			}
			endpoint, err := url.Parse(attr.Value)
			if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") ||
				endpoint.User != nil || endpoint.Path != "/en/" || endpoint.RawQuery != "" ||
				endpoint.Fragment != "" || net.ParseIP(endpoint.Hostname()).To4() == nil ||
				!isPublicIP(endpoint.Hostname()) {
				continue
			}
			if port := endpoint.Port(); port != "" {
				n, err := strconv.Atoi(port)
				if err != nil || n < 1 || n > 65535 {
					continue
				}
			}
			endpoint.Path = "/api/iphone/"
			address := endpoint.String()
			if !seen[address] {
				mirrors = append(mirrors, address)
				seen[address] = true
			}
		}
		if len(mirrors) >= 32 {
			break
		}
	}
	if len(mirrors) == 0 {
		return nil, errors.New("official directory contains no usable mirrors")
	}
	return mirrors, nil
}

func (f *Fetcher) Fetch(ctx context.Context) ([]model.VPNGateCandidate, error) {
	f.mu.RLock()
	primaryURL := f.URL
	mirrors := append([]string(nil), f.MirrorURLs...)
	f.mu.RUnlock()
	urls := []string{primaryURL}
	for _, mirrorURL := range mirrors {
		if mirrorURL != primaryURL {
			urls = append(urls, mirrorURL)
		}
	}

	primaryCtx, cancel := context.WithTimeout(ctx, primaryFetchTimeout)
	candidates, err := f.fetchURL(primaryCtx, urls[0])
	cancel()
	if err == nil {
		if candidates, err = f.filterReachable(ctx, candidates); err == nil {
			return candidates, nil
		}
	}
	failures := []error{fmt.Errorf("%s: %w", urls[0], err)}
	log.Print("VPNGate primary catalog unavailable; trying mirrors")
	if len(urls) == 1 {
		return nil, errors.Join(failures...)
	}

	// A volunteer mirror can accept a TCP connection and then stall while
	// producing the large CSV. Race the mirrors so one slow endpoint cannot
	// consume the reverse proxy's request timeout before a healthy mirror is
	// tried.
	mirrorCtx, cancel := context.WithTimeout(ctx, mirrorFetchTimeout)
	defer cancel()
	type result struct {
		url        string
		candidates []model.VPNGateCandidate
		err        error
	}
	results := make(chan result, len(urls)-1)
	jobs := make(chan string, len(urls)-1)
	for _, url := range urls[1:] {
		jobs <- url
	}
	close(jobs)
	for i := 0; i < 8; i++ {
		go func() {
			for url := range jobs {
				candidates, err := f.fetchURL(mirrorCtx, url)
				results <- result{url: url, candidates: candidates, err: err}
			}
		}()
	}
	for range urls[1:] {
		result := <-results
		if result.err == nil {
			candidates, probeErr := f.filterReachable(mirrorCtx, result.candidates)
			if probeErr == nil {
				return candidates, nil
			}
			result.err = probeErr
		}
		failures = append(failures, fmt.Errorf("%s: %w", result.url, result.err))
	}
	return nil, errors.Join(failures...)
}

func (f *Fetcher) filterReachable(ctx context.Context, candidates []model.VPNGateCandidate) ([]model.VPNGateCandidate, error) {
	if f.Probe == nil {
		return candidates, nil
	}
	parentCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, catalogProbeTimeout)
	defer cancel()
	type result struct {
		candidate model.VPNGateCandidate
		err       error
	}
	results := make(chan result, len(candidates))
	jobs := make(chan model.VPNGateCandidate, len(candidates))
	for _, candidate := range candidates {
		jobs <- candidate
	}
	close(jobs)
	for i := 0; i < 16; i++ {
		go func() {
			for candidate := range jobs {
				probeCtx, cancel := context.WithTimeout(ctx, candidateProbeTimeout)
				err := probeCtx.Err()
				if err == nil {
					err = f.Probe(probeCtx, candidate)
				}
				cancel()
				results <- result{candidate: candidate, err: err}
			}
		}()
	}
	reachable := make([]model.VPNGateCandidate, 0, len(candidates))
	for range candidates {
		result := <-results
		if result.err == nil {
			reachable = append(reachable, result.candidate)
		}
	}
	if parentCtx.Err() != nil {
		return nil, parentCtx.Err()
	}
	log.Printf("VPNGate endpoint response check: %d/%d passed", len(reachable), len(candidates))
	if len(reachable) == 0 {
		return nil, errors.New("VPNGate catalog contains no reachable candidates")
	}
	sortCandidates(reachable)
	return reachable, nil
}

func (f *Fetcher) fetchURL(ctx context.Context, url string) ([]model.VPNGateCandidate, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "J-UI/0.2 (+https://github.com/Suparluxi/j-ui)")
	// VPNGate mirrors can stall indefinitely when Go requests gzip. Request
	// the CSV uncompressed so a broken gzip response cannot block refresh.
	request.Header.Set("Accept-Encoding", "identity")
	response, err := f.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch VPNGate catalog: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch VPNGate catalog: HTTP %d", response.StatusCode)
	}
	if strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/html") {
		return nil, errors.New("VPNGate returned HTML instead of CSV")
	}
	return ParseCSV(io.LimitReader(response.Body, 32<<20), time.Now().UTC())
}

func ParseCSV(reader io.Reader, fetchedAt time.Time) ([]model.VPNGateCandidate, error) {
	parser := csv.NewReader(reader)
	parser.FieldsPerRecord = -1
	parser.ReuseRecord = true
	var candidates []model.VPNGateCandidate
	for {
		record, err := parser.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse VPNGate CSV: %w", err)
		}
		if len(record) == 0 {
			continue
		}
		record[0] = strings.TrimPrefix(record[0], "\ufeff")
		if strings.HasPrefix(record[0], "#") || record[0] == "*" {
			continue
		}
		if len(record) < 15 {
			continue
		}
		ip := strings.TrimSpace(record[1])
		country := strings.ToUpper(strings.TrimSpace(record[6]))
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil || len(country) != 2 {
			continue
		}
		configBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(record[14]))
		if err != nil || len(configBytes) == 0 || len(configBytes) > 2<<20 {
			continue
		}
		candidate := model.VPNGateCandidate{
			HostName: strings.TrimSpace(record[0]), IP: ip,
			Score: parseInt64(record[2]), Ping: int(parseInt64(record[3])),
			Speed: parseInt64(record[4]), CountryLong: strings.TrimSpace(record[5]),
			CountryShort: country, NumSessions: int(parseInt64(record[7])),
			Uptime: parseInt64(record[8]), OpenVPNConfig: string(configBytes),
			HasOpenVPN: true, FetchedAt: fetchedAt,
		}
		if candidate.HostName == "" {
			continue
		}
		candidates = append(candidates, candidate)
		if len(candidates) > 1024 {
			return nil, errors.New("VPNGate catalog exceeds candidate limit")
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("VPNGate catalog contains no usable OpenVPN candidates")
	}
	return candidates, nil
}

func parseInt64(value string) int64 {
	number, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return number
}

type Filter struct {
	Country string
}

func FilterAndRank(candidates []model.VPNGateCandidate, filter Filter, excluded map[string]bool) []model.VPNGateCandidate {
	country := strings.ToUpper(strings.TrimSpace(filter.Country))
	result := make([]model.VPNGateCandidate, 0)
	for _, candidate := range candidates {
		if country != "" && candidate.CountryShort != country {
			continue
		}
		if excluded[candidate.HostName] {
			continue
		}
		result = append(result, candidate)
	}
	sortCandidates(result)
	return result
}

func sortCandidates(candidates []model.VPNGateCandidate) {
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0 && better(candidates[j], candidates[j-1]); j-- {
			candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
		}
	}
}

func better(left, right model.VPNGateCandidate) bool {
	if left.Score != right.Score {
		return left.Score > right.Score
	}
	if left.Speed != right.Speed {
		return left.Speed > right.Speed
	}
	leftPing, rightPing := left.Ping, right.Ping
	if leftPing <= 0 {
		leftPing = int(^uint(0) >> 1)
	}
	if rightPing <= 0 {
		rightPing = int(^uint(0) >> 1)
	}
	if leftPing != rightPing {
		return leftPing < rightPing
	}
	return left.NumSessions < right.NumSessions
}
