package socksbridge

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestReadTargetRejectsIPv6(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		request := []byte{5, 1, 0, 4}
		request = append(request, make([]byte, 16)...)
		request = append(request, 0, 80)
		_, _ = client.Write(request)
	}()
	if _, err := readTarget(context.Background(), server); err == nil {
		t.Fatal("accepted an IPv6 target")
	}
}

func TestHandleAuthenticatedIPv4Connect(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		connection, acceptErr := target.Accept()
		if acceptErr == nil {
			defer connection.Close()
			buffer := make([]byte, 4)
			_, _ = io.ReadFull(connection, buffer)
			_, _ = connection.Write(buffer)
		}
	}()
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		done <- handle(context.Background(), server, Config{Username: "user", Password: "pass"})
	}()
	_, _ = client.Write([]byte{5, 1, 2})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 2 {
		t.Fatalf("method reply = %v err=%v", reply, err)
	}
	_, _ = client.Write([]byte{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'})
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 0 {
		t.Fatalf("auth reply = %v err=%v", reply, err)
	}
	port := target.Addr().(*net.TCPAddr).Port
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)
	_, _ = client.Write(request)
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(client, connectReply); err != nil || connectReply[1] != 0 {
		t.Fatalf("connect reply = %v err=%v", connectReply, err)
	}
	_, _ = client.Write([]byte("ping"))
	echo := make([]byte, 4)
	if _, err := io.ReadFull(client, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo = %q err=%v", echo, err)
	}
	client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServeCancellationClosesActiveConnections(t *testing.T) {
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, Config{
			Listen: address, Username: "user", Password: "pass", MaxConnections: 4,
		})
	}()
	var connection net.Conn
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		connection, err = net.DialTimeout("tcp4", address, 20*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("connect to bridge: %v", err)
	}
	defer connection.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge did not close an active connection after cancellation")
	}
}
