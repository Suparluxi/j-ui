package socksbridge

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Suparluxi/j-ui/internal/tundns"
)

type Config struct {
	Listen         string `json:"listen"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	MaxConnections int    `json:"maxConnections"`
}

func LoadConfig(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Config{}, errors.New("SOCKS bridge config must not be accessible by group or other users")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(content, &config); err != nil {
		return Config{}, err
	}
	host, portText, err := net.SplitHostPort(config.Listen)
	if err != nil || net.ParseIP(host) == nil || net.ParseIP(host).To4() == nil {
		return Config{}, errors.New("SOCKS bridge listen address must use IPv4 and include a port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Config{}, errors.New("SOCKS bridge listen port is invalid")
	}
	if config.Username == "" || config.Password == "" ||
		len(config.Username) > 255 || len(config.Password) > 255 {
		return Config{}, errors.New("SOCKS bridge requires valid username and password")
	}
	if config.MaxConnections < 1 || config.MaxConnections > 4096 {
		config.MaxConnections = 128
	}
	return config, nil
}

func Serve(ctx context.Context, config Config) error {
	listener, err := net.Listen("tcp4", config.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	var connectionsMu sync.Mutex
	connections := make(map[net.Conn]struct{})
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		connectionsMu.Lock()
		for connection := range connections {
			_ = connection.Close()
		}
		connectionsMu.Unlock()
	}()
	limit := make(chan struct{}, config.MaxConnections)
	var active sync.WaitGroup
	defer active.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		connectionsMu.Lock()
		if ctx.Err() != nil {
			connectionsMu.Unlock()
			_ = connection.Close()
			return nil
		}
		connections[connection] = struct{}{}
		connectionsMu.Unlock()
		select {
		case limit <- struct{}{}:
			active.Add(1)
			go func() {
				defer active.Done()
				defer func() { <-limit }()
				defer func() {
					connectionsMu.Lock()
					delete(connections, connection)
					connectionsMu.Unlock()
				}()
				_ = handle(ctx, connection, config)
			}()
		default:
			connectionsMu.Lock()
			delete(connections, connection)
			connectionsMu.Unlock()
			_ = connection.Close()
		}
	}
}

func handle(ctx context.Context, client net.Conn, config Config) error {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil || header[0] != 5 || header[1] == 0 {
		return errors.New("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return err
	}
	supportsAuth := false
	for _, method := range methods {
		if method == 2 {
			supportsAuth = true
		}
	}
	if !supportsAuth {
		_, _ = client.Write([]byte{5, 0xff})
		return errors.New("SOCKS5 client did not offer username/password authentication")
	}
	if _, err := client.Write([]byte{5, 2}); err != nil {
		return err
	}
	if err := authenticate(client, config); err != nil {
		_, _ = client.Write([]byte{1, 1})
		return err
	}
	if _, err := client.Write([]byte{1, 0}); err != nil {
		return err
	}
	target, err := readTarget(ctx, client)
	if err != nil {
		_, _ = client.Write(socksReply(8))
		return err
	}
	upstream, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp4", target)
	if err != nil {
		_, _ = client.Write(socksReply(5))
		return err
	}
	defer upstream.Close()
	if _, err := client.Write(socksReply(0)); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	copyStream := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		if tcp, ok := destination.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyStream(upstream, client)
	go copyStream(client, upstream)
	<-done
	return nil
}

func authenticate(connection net.Conn, config Config) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 1 {
		return errors.New("invalid RFC 1929 authentication request")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, username); err != nil {
		return err
	}
	length := []byte{0}
	if _, err := io.ReadFull(connection, length); err != nil {
		return err
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(connection, password); err != nil {
		return err
	}
	userMatch := subtle.ConstantTimeCompare(username, []byte(config.Username))
	passwordMatch := subtle.ConstantTimeCompare(password, []byte(config.Password))
	if userMatch&passwordMatch != 1 {
		return errors.New("SOCKS5 credentials rejected")
	}
	return nil
}

func readTarget(ctx context.Context, connection net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", err
	}
	if header[0] != 5 || header[1] != 1 {
		return "", errors.New("only SOCKS5 CONNECT is supported")
	}
	var host string
	switch header[3] {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(connection, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil || length[0] == 0 {
			return "", errors.New("invalid SOCKS5 hostname")
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(connection, name); err != nil {
			return "", err
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		addresses, err := tundns.IPv4Dialer().Resolver.LookupIP(lookupCtx, "ip4", string(name))
		if err != nil || len(addresses) == 0 {
			return "", errors.New("SOCKS5 hostname has no IPv4 address")
		}
		host = addresses[0].String()
	case 4:
		return "", errors.New("IPv6 targets are blocked by the VPNGate bridge")
	default:
		return "", errors.New("invalid SOCKS5 address type")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	if port == 0 {
		return "", errors.New("invalid target port")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func socksReply(code byte) []byte {
	return []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
}

func WriteConfig(path string, config Config) error {
	content, err := json.Marshal(config)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("activate SOCKS bridge config: %w", err)
	}
	return nil
}
