package vpngate

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

const DefaultAPIURL = "https://www.vpngate.net/api/iphone/"

type Fetcher struct {
	URL    string
	Client *http.Client
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		URL:    DefaultAPIURL,
		Client: &http.Client{Timeout: 20 * time.Second},
	}
}

func (f *Fetcher) Fetch(ctx context.Context) ([]model.VPNGateCandidate, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "J-UI/0.2 (+https://github.com/Suparluxi/j-ui)")
	response, err := f.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch VPNGate catalog: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch VPNGate catalog: HTTP %d", response.StatusCode)
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
