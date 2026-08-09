package exitcheck

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

type Result struct {
	IP      string
	Country string
	ASN     string
}

type Checker struct {
	IPURL   string
	GeoURL  string
	Timeout time.Duration
}

func New() *Checker {
	return &Checker{
		IPURL:   "https://api64.ipify.org?format=json",
		GeoURL:  "https://ipwho.is/",
		Timeout: 10 * time.Second,
	}
}

func (c *Checker) Check(ctx context.Context, outbound model.Outbound) (Result, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			switch outbound.Type {
			case model.OutboundSOCKS5:
				return dialSOCKS5(ctx, outbound, address)
			case model.OutboundHTTP:
				return dialHTTPConnect(ctx, outbound, address)
			default:
				return nil, fmt.Errorf("unsupported outbound type %q", outbound.Type)
			}
		},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.IPURL, nil)
	if err != nil {
		return Result{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return Result{}, fmt.Errorf("query exit IP: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("query exit IP: unexpected HTTP status %d", response.StatusCode)
	}
	var ipResponse struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&ipResponse); err != nil {
		return Result{}, fmt.Errorf("decode exit IP: %w", err)
	}
	ipResponse.IP = strings.TrimSpace(ipResponse.IP)
	if net.ParseIP(ipResponse.IP) == nil {
		return Result{}, errors.New("exit service returned an invalid IP")
	}

	result := Result{IP: ipResponse.IP}
	geoRequest, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		c.GeoURL+url.PathEscape(ipResponse.IP)+"?fields=success,message,country_code,connection.asn,connection.org",
		nil,
	)
	if err != nil {
		return result, nil
	}
	geoResponse, err := http.DefaultClient.Do(geoRequest)
	if err != nil {
		return result, nil
	}
	defer geoResponse.Body.Close()
	if geoResponse.StatusCode != http.StatusOK {
		return result, nil
	}
	var geo struct {
		Success     bool   `json:"success"`
		CountryCode string `json:"country_code"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
		} `json:"connection"`
	}
	if json.NewDecoder(io.LimitReader(geoResponse.Body, 64<<10)).Decode(&geo) == nil && geo.Success {
		result.Country = geo.CountryCode
		if geo.Connection.ASN != 0 {
			result.ASN = "AS" + strconv.Itoa(geo.Connection.ASN)
			if geo.Connection.Org != "" {
				result.ASN += " " + geo.Connection.Org
			}
		}
	}
	return result, nil
}

func dialSOCKS5(ctx context.Context, outbound model.Outbound, target string) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(outbound.Server, strconv.Itoa(outbound.Port)))
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			connection.Close()
		}
	}()
	if deadline, exists := ctx.Deadline(); exists {
		_ = connection.SetDeadline(deadline)
		defer connection.SetDeadline(time.Time{})
	}
	methods := []byte{0}
	if outbound.Username != "" || outbound.Password != "" {
		methods = append(methods, 2)
	}
	if _, err := connection.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(connection, reply); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] == 0xff {
		return nil, errors.New("SOCKS5 proxy rejected authentication methods")
	}
	if reply[1] == 2 {
		if len(outbound.Username) > 255 || len(outbound.Password) > 255 {
			return nil, errors.New("SOCKS5 credentials are too long")
		}
		auth := []byte{1, byte(len(outbound.Username))}
		auth = append(auth, outbound.Username...)
		auth = append(auth, byte(len(outbound.Password)))
		auth = append(auth, outbound.Password...)
		if _, err := connection.Write(auth); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(connection, reply); err != nil {
			return nil, err
		}
		if reply[1] != 0 {
			return nil, errors.New("SOCKS5 username or password was rejected")
		}
	} else if reply[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 proxy selected unsupported method %d", reply[1])
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 1)
			request = append(request, ipv4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("target hostname is too long")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)
	if _, err := connection.Write(request); err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 CONNECT failed with code %d", header[1])
	}
	var addressLength int
	switch header[3] {
	case 1:
		addressLength = 4
	case 4:
		addressLength = 16
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil {
			return nil, err
		}
		addressLength = int(length[0])
	default:
		return nil, errors.New("SOCKS5 proxy returned an invalid address type")
	}
	if _, err := io.ReadFull(connection, make([]byte, addressLength+2)); err != nil {
		return nil, err
	}
	ok = true
	return connection, nil
}

func dialHTTPConnect(ctx context.Context, outbound model.Outbound, target string) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(outbound.Server, strconv.Itoa(outbound.Port)))
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			connection.Close()
		}
	}()
	if deadline, exists := ctx.Deadline(); exists {
		_ = connection.SetDeadline(deadline)
		defer connection.SetDeadline(time.Time{})
	}
	headers := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if outbound.Username != "" || outbound.Password != "" {
		credential := base64.StdEncoding.EncodeToString([]byte(outbound.Username + ":" + outbound.Password))
		headers += "Proxy-Authorization: Basic " + credential + "\r\n"
	}
	if _, err := io.WriteString(connection, headers+"\r\n"); err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP proxy CONNECT failed with status %d", response.StatusCode)
	}
	ok = true
	return connection, nil
}
