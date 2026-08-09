package exitcheck

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/Suparluxi/j-ui/internal/model"
)

func TestDialSOCKS5WithAuthentication(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErrors := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverErrors <- err
			return
		}
		defer connection.Close()
		greeting := make([]byte, 4)
		if _, err := io.ReadFull(connection, greeting); err != nil {
			serverErrors <- err
			return
		}
		if _, err := connection.Write([]byte{5, 2}); err != nil {
			serverErrors <- err
			return
		}
		auth := make([]byte, 1+1+4+1+4)
		if _, err := io.ReadFull(connection, auth); err != nil {
			serverErrors <- err
			return
		}
		if _, err := connection.Write([]byte{1, 0}); err != nil {
			serverErrors <- err
			return
		}
		header := make([]byte, 5)
		if _, err := io.ReadFull(connection, header); err != nil {
			serverErrors <- err
			return
		}
		host := make([]byte, int(header[4])+2)
		if _, err := io.ReadFull(connection, host); err != nil {
			serverErrors <- err
			return
		}
		_, err = connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
		serverErrors <- err
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	connection, err := dialSOCKS5(context.Background(), model.Outbound{
		Type: model.OutboundSOCKS5, Server: host, Port: port,
		Username: "user", Password: "pass",
	}, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestDialHTTPConnectUsesBasicAuthentication(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan string, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			requests <- acceptErr.Error()
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		var lines []string
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				requests <- readErr.Error()
				return
			}
			lines = append(lines, line)
			if line == "\r\n" {
				break
			}
		}
		requests <- strings.Join(lines, "")
		_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	connection, err := dialHTTPConnect(context.Background(), model.Outbound{
		Type: model.OutboundHTTP, Server: host, Port: port,
		Username: "user", Password: "pass",
	}, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	request := <-requests
	if !strings.Contains(request, "CONNECT example.com:443 HTTP/1.1") ||
		!strings.Contains(request, "Proxy-Authorization: Basic dXNlcjpwYXNz") {
		t.Fatalf("unexpected CONNECT request:\n%s", request)
	}
}
