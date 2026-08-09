package vpngate

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Remote struct {
	Protocol string
	IP       string
	Port     int
}

var forbiddenDirectives = map[string]bool{
	"script-security": true, "up": true, "down": true, "route-up": true,
	"route-pre-down": true, "plugin": true, "management": true,
	"client-connect": true, "client-disconnect": true, "learn-address": true,
	"daemon": true, "log": true, "log-append": true, "writepid": true,
	"chroot": true, "cd": true, "config": true, "setenv": true,
}

var allowedDirectives = map[string]bool{
	"client": true, "dev": true, "dev-type": true, "proto": true,
	"resolv-retry": true, "nobind": true, "persist-key": true, "persist-tun": true,
	"cipher": true, "data-ciphers": true, "data-ciphers-fallback": true,
	"auth": true, "auth-nocache": true, "remote-cert-tls": true,
	"tls-client": true, "tls-version-min": true, "key-direction": true,
	"verb": true, "mute": true, "ping": true, "ping-restart": true,
	"connect-retry": true, "connect-timeout": true,
}

var allowedBlocks = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
}

func SanitizeOpenVPN(raw, expectedIP string) (string, Remote, error) {
	if net.ParseIP(expectedIP) == nil || net.ParseIP(expectedIP).To4() == nil {
		return "", Remote{}, errors.New("expected VPNGate endpoint must be an IPv4 address")
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	var output []string
	var protocol string
	var remotes []Remote
	var block string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if block != "" {
			output = append(output, line)
			if strings.EqualFold(line, "</"+block+">") {
				block = ""
			}
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			name := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(line), "<"), ">")
			if strings.HasPrefix(name, "/") || !allowedBlocks[name] {
				return "", Remote{}, fmt.Errorf("OpenVPN block %q is not allowed", name)
			}
			block = name
			output = append(output, "<"+name+">")
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])
		if forbiddenDirectives[directive] {
			return "", Remote{}, fmt.Errorf("OpenVPN directive %q is forbidden", directive)
		}
		switch directive {
		case "remote":
			if len(fields) < 3 {
				return "", Remote{}, errors.New("OpenVPN remote directive is incomplete")
			}
			port, err := strconv.Atoi(fields[2])
			if err != nil || port < 1 || port > 65535 {
				return "", Remote{}, errors.New("OpenVPN remote port is invalid")
			}
			remoteProtocol := protocol
			if len(fields) >= 4 {
				remoteProtocol = normalizeProto(fields[3])
			}
			remotes = append(remotes, Remote{Protocol: remoteProtocol, IP: expectedIP, Port: port})
		case "proto":
			if len(fields) != 2 {
				return "", Remote{}, errors.New("OpenVPN proto directive is invalid")
			}
			protocol = normalizeProto(fields[1])
			if protocol == "" {
				return "", Remote{}, errors.New("only UDP or TCP OpenVPN transports are allowed")
			}
		default:
			if !allowedDirectives[directive] {
				return "", Remote{}, fmt.Errorf("OpenVPN directive %q is not allowlisted", directive)
			}
			if directive == "dev" && (len(fields) != 2 || fields[1] != "tun") {
				return "", Remote{}, errors.New("VPNGate OpenVPN configuration must use dev tun")
			}
			output = append(output, strings.Join(fields, " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return "", Remote{}, err
	}
	if block != "" {
		return "", Remote{}, fmt.Errorf("OpenVPN block %q is not closed", block)
	}
	if len(remotes) == 0 {
		return "", Remote{}, errors.New("OpenVPN configuration has no remote endpoint")
	}
	for index := range remotes {
		if remotes[index].Protocol == "" {
			remotes[index].Protocol = protocol
		}
		if remotes[index].Protocol == "" {
			remotes[index].Protocol = "udp"
		}
	}
	selected := chooseRemote(remotes)
	output = append(output,
		"proto "+selected.Protocol,
		fmt.Sprintf("remote %s %d", selected.IP, selected.Port),
		"route-nopull",
		"redirect-gateway def1",
		`pull-filter ignore "dhcp-option"`,
		`pull-filter ignore "route"`,
		"auth-nocache",
		"verb 3",
	)
	return strings.Join(output, "\n") + "\n", selected, nil
}

func normalizeProto(value string) string {
	switch strings.ToLower(value) {
	case "udp", "udp4":
		return "udp"
	case "tcp", "tcp4", "tcp-client":
		return "tcp-client"
	default:
		return ""
	}
}

func chooseRemote(remotes []Remote) Remote {
	selected := remotes[0]
	for _, remote := range remotes {
		if remote.Protocol == "udp" && (selected.Protocol != "udp" ||
			(remote.Port < 2000 && selected.Port >= 2000)) {
			selected = remote
		}
	}
	return selected
}
