package vpngate

import (
	"strings"
	"testing"
)

const safeOpenVPN = `
client
dev tun
proto udp
remote malicious.example 443
remote malicious.example 1194 udp
nobind
persist-key
persist-tun
cipher AES-128-CBC
auth SHA1
<ca>
TEST CA
</ca>
<cert>
TEST CERT
</cert>
<key>
TEST KEY
</key>
`

func TestSanitizeOpenVPNPinsRemoteAndAddsNoFallbackRoutes(t *testing.T) {
	config, remote, err := SanitizeOpenVPN(safeOpenVPN, "198.51.100.20")
	if err != nil {
		t.Fatal(err)
	}
	if remote.IP != "198.51.100.20" || remote.Protocol != "udp" || remote.Port != 443 {
		t.Fatalf("selected remote = %#v", remote)
	}
	for _, expected := range []string{
		"remote 198.51.100.20 443", "route-nopull", "redirect-gateway def1",
		`pull-filter ignore "dhcp-option"`, `pull-filter ignore "route"`,
	} {
		if !strings.Contains(config, expected) {
			t.Fatalf("sanitized config lacks %q:\n%s", expected, config)
		}
	}
	if strings.Contains(config, "malicious.example") {
		t.Fatalf("sanitized config retained untrusted remote:\n%s", config)
	}
}

func TestSanitizeOpenVPNRejectsCommandHooks(t *testing.T) {
	for _, directive := range []string{
		"script-security 2", "up /tmp/pwn", "plugin evil.so", "config other.ovpn",
	} {
		if _, _, err := SanitizeOpenVPN(safeOpenVPN+"\n"+directive+"\n", "198.51.100.20"); err == nil {
			t.Fatalf("accepted forbidden directive %q", directive)
		}
	}
}

func TestSanitizeOpenVPNRejectsUnknownDirectiveAndNonTun(t *testing.T) {
	if _, _, err := SanitizeOpenVPN("client\ndev tap\nremote x 1194\n", "198.51.100.20"); err == nil {
		t.Fatal("accepted dev tap")
	}
	if _, _, err := SanitizeOpenVPN(safeOpenVPN+"\nunknown-option yes\n", "198.51.100.20"); err == nil {
		t.Fatal("accepted unknown directive")
	}
}

func TestSanitizeOpenVPNAppliesProtoDeclaredAfterRemote(t *testing.T) {
	_, remote, err := SanitizeOpenVPN(
		"client\ndev tun\nremote vpn.example 443\nproto tcp-client\n<ca>\nCA\n</ca>\n",
		"198.51.100.20",
	)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Protocol != "tcp-client" || remote.Port != 443 {
		t.Fatalf("selected remote = %#v", remote)
	}
}
