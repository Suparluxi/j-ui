package vpngate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

// The reset exchange checks OpenVPN responsiveness, not TLS authentication or
// usable tunnel routing. Provision still verifies both before enabling traffic.
func probeCandidate(ctx context.Context, candidate model.VPNGateCandidate) error {
	if !isPublicIP(candidate.IP) {
		return errors.New("candidate endpoint is not public")
	}
	config, remote, err := SanitizeOpenVPN(candidate.OpenVPNConfig, candidate.IP)
	if err != nil {
		return err
	}
	if strings.Contains(config, "<tls-auth>") || strings.Contains(config, "<tls-crypt>") {
		return errors.New("authenticated control packets require full tunnel verification")
	}
	ctx, cancel := context.WithTimeout(ctx, candidateProbeTimeout)
	defer cancel()
	network := "udp4"
	if remote.Protocol == "tcp-client" {
		network = "tcp4"
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(remote.IP, strconv.Itoa(remote.Port)))
	if err != nil {
		return err
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	return probeOpenVPN(ctx, connection, network == "tcp4")
}

func probeOpenVPN(ctx context.Context, connection net.Conn, tcp bool) error {
	// V2 client reset: opcode/key-id, 8-byte session, no ACKs, packet-id zero.
	packet := make([]byte, 14)
	packet[0] = 7 << 3
	if _, err := rand.Read(packet[1:9]); err != nil {
		return err
	}
	wire := packet
	if tcp {
		wire = append([]byte{0, byte(len(packet))}, packet...)
	}
	attempts := 1
	if !tcp {
		attempts = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if _, err := io.Copy(connection, bytes.NewReader(wire)); err != nil {
			return err
		}
		deadline, _ := ctx.Deadline()
		if !tcp && attempt == 0 {
			deadline = time.Now().Add(time.Until(deadline) / 2)
		}
		if err := connection.SetReadDeadline(deadline); err != nil {
			return err
		}
		response := make([]byte, 2048)
		var n int
		var err error
		if tcp {
			var size [2]byte
			if _, err = io.ReadFull(connection, size[:]); err != nil {
				return err
			}
			n = int(binary.BigEndian.Uint16(size[:]))
			if n > len(response) {
				return errors.New("oversized OpenVPN reset response")
			}
			_, err = io.ReadFull(connection, response[:n])
		} else {
			n, err = connection.Read(response)
		}
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() && attempt+1 < attempts {
				continue
			}
			return err
		}
		if validResetResponse(response[:n], packet[1:9]) {
			return nil
		}
		return errors.New("invalid OpenVPN server reset response")
	}
	return errors.New("no OpenVPN reset response")
}

func validResetResponse(packet, session []byte) bool {
	if len(packet) < 10 || packet[0] != 8<<3 {
		return false
	}
	count := int(packet[9])
	offset := 10 + count*4
	if count == 0 || len(packet) < offset+12 {
		return false
	}
	// The server must ACK our reset (packet-id zero) and echo our session.
	if !bytes.Equal(packet[offset:offset+8], session) {
		return false
	}
	for i := 0; i < count; i++ {
		if binary.BigEndian.Uint32(packet[10+i*4:14+i*4]) == 0 {
			return true
		}
	}
	return false
}
