package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSLScriptIssuesDomainAndIPv4Certificates(t *testing.T) {
	for _, test := range []struct {
		name            string
		host            string
		want            string
		certificateOnly bool
	}{
		{name: "domain", host: "node.example.com", want: "-d node.example.com"},
		{name: "ipv4", host: "198.51.100.10", want: "--preferred-profile shortlived --ip-address 198.51.100.10"},
		{name: "ipv4 certificate only", host: "198.51.100.11", want: "--preferred-profile shortlived --ip-address 198.51.100.11", certificateOnly: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			script, err := os.ReadFile("ssl.sh")
			if err != nil {
				t.Fatal(err)
			}
			rewritten := string(script)
			for old, replacement := range map[string]string{
				"/opt/j-ui/certbot":                      filepath.Join(root, "opt/j-ui/certbot"),
				"/usr/local/bin/j-ui":                    filepath.Join(root, "usr/local/bin/j-ui"),
				"/etc/letsencrypt":                       filepath.Join(root, "etc/letsencrypt"),
				"/etc/j-ui":                              filepath.Join(root, "etc/j-ui"),
				"if [[ ${EUID:-$(id -u)} -ne 0 ]]; then": "if false; then",
			} {
				rewritten = strings.ReplaceAll(rewritten, old, replacement)
			}
			scriptPath := filepath.Join(root, "ssl.sh")
			writeFixtureFile(t, scriptPath, rewritten, 0o700)
			logPath := filepath.Join(root, "commands.log")
			writeFixtureFile(t, filepath.Join(root, "usr/local/bin/j-ui"), `#!/bin/sh
printf 'j-ui %s\n' "$*" >>"$TEST_LOG"
exit 0
`, 0o755)
			writeFixtureFile(t, filepath.Join(root, "opt/j-ui/certbot/bin/certbot"), `#!/bin/sh
printf 'certbot %s\n' "$*" >>"$TEST_LOG"
host=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -d|--ip-address) host="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$TEST_LETSENCRYPT/live/$host"
printf cert >"$TEST_LETSENCRYPT/live/$host/fullchain.pem"
printf key >"$TEST_LETSENCRYPT/live/$host/privkey.pem"
`, 0o755)
			if err := os.MkdirAll(filepath.Join(root, "etc/j-ui"), 0o700); err != nil {
				t.Fatal(err)
			}

			arguments := []string{scriptPath, test.host}
			if test.certificateOnly {
				arguments = []string{scriptPath, "--certificate-only", test.host}
				environmentPath := filepath.Join(root, "etc/j-ui/j-ui.env")
				writeFixtureFile(t, environmentPath, "JUI_TLS_CERTIFICATE_PATH=/panel/cert.pem\nJUI_TLS_KEY_PATH=/panel/key.pem\n", 0o600)
			}
			command := exec.Command("bash", arguments...)
			command.Env = append(os.Environ(),
				"TEST_LOG="+logPath,
				"TEST_LETSENCRYPT="+filepath.Join(root, "etc/letsencrypt"),
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("ssl script failed: %v\n%s", err, output)
			}
			log, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(log), test.want) {
				t.Fatalf("certificate arguments missing %q:\n%s", test.want, log)
			}
			if !strings.Contains(string(log), "j-ui ensure-acme-firewall") ||
				!strings.Contains(string(log), "j-ui close-acme-firewall") {
				t.Fatalf("temporary ACME firewall lifecycle missing:\n%s", log)
			}
			if test.certificateOnly {
				environment, err := os.ReadFile(filepath.Join(root, "etc/j-ui/j-ui.env"))
				if err != nil {
					t.Fatal(err)
				}
				if string(environment) != "JUI_TLS_CERTIFICATE_PATH=/panel/cert.pem\nJUI_TLS_KEY_PATH=/panel/key.pem\n" {
					t.Fatalf("certificate-only mode changed panel TLS settings:\n%s", environment)
				}
				if strings.Contains(string(log), "configure-install") {
					t.Fatalf("certificate-only mode reconfigured panel TLS:\n%s", log)
				}
			}
		})
	}
}
