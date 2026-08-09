package scripts_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallContinuesRollbackAndPreservesRecoveryFiles(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture archive name is amd64")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(root, "release")
	writeFixtureFile(t, filepath.Join(release, "j-ui"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFixtureFile(t, filepath.Join(release, "sing-box"), "#!/bin/sh\nif [ \"${1:-}\" = version ]; then echo 'sing-box version 1.13.16'; fi\nexit 0\n", 0o755)
	for _, path := range []string{
		"deploy/j-ui.service", "deploy/j-ui-update.service", "deploy/j-ui-sing-box.service",
		"deploy/j-ui-certificate-renew.service", "deploy/j-ui-certificate-renew.timer",
		"deploy/j-ui-certificate-issue@.service",
		"deploy/j-ui.env", "deploy/empty-sing-box.json",
		"scripts/update.sh", "scripts/uninstall.sh", "scripts/manage.sh", "scripts/ssl.sh", "scripts/argo.sh",
	} {
		writeFixtureFile(t, filepath.Join(release, path), "new-"+path+"\n", 0o755)
	}
	releaseArchive := filepath.Join(root, "j-ui_0.1.0_linux_amd64.tar.gz")
	createArchive(t, releaseArchive, release)
	releaseBytes, err := os.ReadFile(releaseArchive)
	if err != nil {
		t.Fatal(err)
	}
	checksums := filepath.Join(root, "checksums.txt")
	if err := os.WriteFile(checksums, []byte(fmt.Sprintf(
		"%x  j-ui_0.1.0_linux_amd64.tar.gz\n", sha256.Sum256(releaseBytes),
	)), 0o600); err != nil {
		t.Fatal(err)
	}
	replacements := [][2]string{
		{"/usr/local/lib/j-ui/sing-box", filepath.Join(root, "usr/local/lib/j-ui/sing-box")},
		{"/usr/local/lib/j-ui", filepath.Join(root, "usr/local/lib/j-ui")},
		{"/usr/local/bin/j-ui", filepath.Join(root, "usr/local/bin/j-ui")},
		{"/usr/local/bin/jui", filepath.Join(root, "usr/local/bin/jui")},
		{"/usr/local/bin/J-UI", filepath.Join(root, "usr/local/bin/J-UI")},
		{"/usr/local/bin/J-Ui", filepath.Join(root, "usr/local/bin/J-Ui")},
		{"/usr/local/bin/J-uI", filepath.Join(root, "usr/local/bin/J-uI")},
		{"/usr/local/bin/J-ui", filepath.Join(root, "usr/local/bin/J-ui")},
		{"/usr/local/bin/j-UI", filepath.Join(root, "usr/local/bin/j-UI")},
		{"/usr/local/bin/j-Ui", filepath.Join(root, "usr/local/bin/j-Ui")},
		{"/usr/local/bin/j-uI", filepath.Join(root, "usr/local/bin/j-uI")},
		{"/etc/systemd/system", filepath.Join(root, "etc/systemd/system")},
		{"/etc/sysctl.d/99-j-ui-bbr.conf", filepath.Join(root, "etc/sysctl.d/99-j-ui-bbr.conf")},
		{"/var/backups/j-ui", filepath.Join(root, "var/backups/j-ui")},
		{"/var/lib/j-ui", filepath.Join(root, "var/lib/j-ui")},
		{"/etc/j-ui", filepath.Join(root, "etc/j-ui")},
		{"/run/lock/j-ui-lifecycle.lock", filepath.Join(root, "run/lock/j-ui-lifecycle.lock")},
		{"/opt/j-ui/certbot", filepath.Join(root, "opt/j-ui/certbot")},
		{"/tmp/j-ui-install.", filepath.Join(root, "tmp/j-ui-install.")},
		{"/etc/os-release", filepath.Join(root, "os-release")},
		{"/dev/net/tun", filepath.Join(root, "missing-tun")},
		{"if [[ ${EUID:-$(id -u)} -ne 0 ]]; then", "if false; then"},
	}
	rewritten := string(script)
	for _, replacement := range replacements {
		rewritten = strings.ReplaceAll(rewritten, replacement[0], replacement[1])
	}
	scriptPath := filepath.Join(root, "install.sh")
	if err := os.WriteFile(scriptPath, []byte(rewritten), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(root, "os-release"),
		"ID=debian\nVERSION_ID=12\n", 0o600)
	if err := os.MkdirAll(filepath.Join(root, "run/lock"), 0o700); err != nil {
		t.Fatal(err)
	}

	managed := []string{
		filepath.Join(root, "usr/local/bin/j-ui"),
		filepath.Join(root, "usr/local/bin/jui"),
		filepath.Join(root, "usr/local/bin/J-UI"),
		filepath.Join(root, "usr/local/bin/J-Ui"),
		filepath.Join(root, "usr/local/bin/J-uI"),
		filepath.Join(root, "usr/local/bin/J-ui"),
		filepath.Join(root, "usr/local/bin/j-UI"),
		filepath.Join(root, "usr/local/bin/j-Ui"),
		filepath.Join(root, "usr/local/bin/j-uI"),
		filepath.Join(root, "usr/local/bin/jui-menu"),
		filepath.Join(root, "usr/local/lib/j-ui/sing-box"),
		filepath.Join(root, "etc/sysctl.d/99-j-ui-bbr.conf"),
		filepath.Join(root, "etc/systemd/system/j-ui.service"),
		filepath.Join(root, "etc/systemd/system/j-ui-update.service"),
		filepath.Join(root, "etc/systemd/system/j-ui-sing-box.service"),
		filepath.Join(root, "etc/systemd/system/j-ui-certificate-renew.service"),
		filepath.Join(root, "etc/systemd/system/j-ui-certificate-renew.timer"),
		filepath.Join(root, "usr/local/lib/j-ui/update.sh"),
		filepath.Join(root, "usr/local/lib/j-ui/uninstall.sh"),
		filepath.Join(root, "usr/local/lib/j-ui/manage.sh"),
		filepath.Join(root, "usr/local/lib/j-ui/ssl.sh"),
	}
	oldContents := make(map[string][]byte)
	for index, target := range managed {
		content := []byte(fmt.Sprintf("old-managed-%d\n", index))
		writeFixtureFile(t, target, string(content), 0o700)
		oldContents[target] = content
	}
	for _, target := range []string{
		filepath.Join(root, "etc/j-ui/j-ui.env"),
		filepath.Join(root, "var/lib/j-ui/j-ui.db"),
	} {
		writeFixtureFile(t, target, "old-tree\n", 0o600)
		oldContents[target] = []byte("old-tree\n")
	}

	fakeBin := filepath.Join(root, "fake-bin")
	if err := os.MkdirAll(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(fakeBin, "apt-get"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFixtureFile(t, filepath.Join(fakeBin, "ss"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFixtureFile(t, filepath.Join(fakeBin, "systemctl"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFixtureFile(t, filepath.Join(fakeBin, "modprobe"), "#!/bin/sh\nexit 0\n", 0o755)
	sysctlState := filepath.Join(root, "sysctl-state")
	writeFixtureFile(t, sysctlState, "fq_codel\ncubic\n", 0o600)
	writeFixtureFile(t, filepath.Join(fakeBin, "sysctl"), `#!/bin/sh
set -eu
qdisc="$(sed -n '1p' "$TEST_SYSCTL_STATE")"
congestion="$(sed -n '2p' "$TEST_SYSCTL_STATE")"
if [ "${1:-}" = "-n" ]; then
  case "$2" in
    net.core.default_qdisc) printf '%s\n' "$qdisc" ;;
    net.ipv4.tcp_congestion_control) printf '%s\n' "$congestion" ;;
    net.ipv4.tcp_available_congestion_control) printf '%s\n' 'reno cubic bbr' ;;
  esac
  exit 0
fi
last=""
for argument in "$@"; do last="$argument"; done
case "$last" in
  net.core.default_qdisc=*) qdisc="${last#*=}" ;;
  net.ipv4.tcp_congestion_control=*) congestion="${last#*=}" ;;
esac
printf '%s\n%s\n' "$qdisc" "$congestion" >"$TEST_SYSCTL_STATE"
`, 0o755)
	writeFixtureFile(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
set -eu
url="${2:-}"
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; break; fi
  shift
done
if [ -z "$output" ]; then exit 0; fi
case "$url" in
  *checksums.txt) /bin/cp "$TEST_CHECKSUMS" "$output" ;;
  *) /bin/cp "$TEST_RELEASE_ARCHIVE" "$output" ;;
esac
`, 0o755)
	failTarget := filepath.Join(root, "usr/local/lib/j-ui/update.sh")
	writeFixtureFile(t, filepath.Join(fakeBin, "install"), `#!/bin/sh
set -eu
last=""
for argument in "$@"; do last="$argument"; done
if [ "$last" = "$TEST_FAIL_TARGET" ]; then exit 73; fi
exec /usr/bin/install "$@"
`, 0o755)
	writeFixtureFile(t, filepath.Join(fakeBin, "cp"), `#!/bin/sh
set -eu
source_path=""
for argument in "$@"; do
  case "$argument" in -*) ;; *) source_path="$argument"; break ;; esac
done
case "$source_path" in
  */rollback*/etc/systemd/system/j-ui.service) exit 74 ;;
esac
exec /bin/cp "$@"
`, 0o755)

	command := exec.Command("bash", scriptPath)
	command.Env = append(os.Environ(),
		"JUI_VERSION=0.1.0",
		"TEST_CHECKSUMS="+checksums,
		"TEST_RELEASE_ARCHIVE="+releaseArchive,
		"TEST_FAIL_TARGET="+failTarget,
		"JUI_ENABLE_BBR=yes",
		"TEST_SYSCTL_STATE="+sysctlState,
		"PATH="+fakeBin+":"+os.Getenv("PATH"),
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("install unexpectedly succeeded\n%s", output)
	}
	if !bytes.Contains(output, []byte("automatic rollback both failed")) {
		t.Fatalf("incomplete rollback warning missing\n%s", output)
	}
	for target, expected := range oldContents {
		if target == filepath.Join(root, "etc/systemd/system/j-ui.service") {
			continue
		}
		content, readErr := os.ReadFile(target)
		if readErr != nil || !bytes.Equal(content, expected) {
			t.Fatalf("rollback content %s=%q err=%v", target, content, readErr)
		}
	}
	bbrState, stateErr := os.ReadFile(sysctlState)
	if stateErr != nil || string(bbrState) != "fq_codel\ncubic\n" {
		t.Fatalf("BBR live settings were not rolled back: %q err=%v", bbrState, stateErr)
	}
	recovery, globErr := filepath.Glob(filepath.Join(root, "tmp/j-ui-install.*"))
	if globErr != nil || len(recovery) != 1 {
		t.Fatalf("recovery directories=%#v err=%v\n%s", recovery, globErr, output)
	}
}

func TestInstallConfiguresNodeStartPort(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`readonly singbox_version="1.13.16"`,
		`install -m 0755 "${temporary_directory}/sing-box" /usr/local/lib/j-ui/sing-box`,
		`confirm_port) printf 'The current node start port is %s. Use the default configuration [Y/n]: '`,
		`ask_yes_no "$(i18n confirm_port "$node_start_port")" yes`,
		`node_start_port="${JUI_NODE_START_PORT:-${configured_node_start_port:-8881}}"`,
		`curl -4 -fsSL --max-time 5 'https://api.ipify.org'`,
		`detected_public_host="${JUI_PUBLIC_HOST:-}"`,
		`detected_public_host="$(detect_public_ip)"`,
		`installation_listen="${JUI_LISTEN_ADDRESS:-${installation_listen:-0.0.0.0:8443}}"`,
		`if [[ $preserve_existing_data -eq 1 && -r /etc/j-ui/j-ui.env ]]; then`,
		`if [[ "$public_host" == *:* ]]; then`,
		`JUI_NODE_START_PORT="${node_start_port}" /usr/local/bin/j-ui init`,
		`management_url="https://${url_host}:${management_port}${web_base_path}"`,
		`/usr/local/bin/j-ui ensure-management-firewall`,
		`systemctl is-enabled --quiet j-ui.service >/dev/null 2>&1`,
		`systemctl is-active --quiet j-ui.service >/dev/null 2>&1`,
		`systemctl is-active --quiet j-ui-sing-box.service >/dev/null 2>&1`,
		`for _ in {1..60}; do`,
		`curl --http1.1 -kfsS --max-time 2 "$health_url" >/dev/null 2>&1`,
		`login_url="${health_url%/api/v1/health}/api/v1/auth/login"`,
		`--arg username "$admin_username" --arg password "$admin_password"`,
		`curl --http1.1 -ksS --max-time 5 -o "$login_response_file"`,
		`-w '%{http_code}' -c "$login_cookie_file"`,
		`for _ in {1..5}; do`,
		`[[ "$(jq -r '.username // empty' <<<"$login_response")" == "$admin_username" ]]`,
		`credentials_verification_unavailable`,
		`i18n health_check_failed`,
		`render_profile_header`,
		`render_management_help`,
		`j-ui settings`,
		`j-ui uninstall`,
		`j-ui ssl`,
		`'certbot==5.7.0'`,
		`/usr/local/lib/j-ui/ssl.sh "$public_host"`,
		`j-ui-certificate-renew.timer`,
		`j-ui-certificate-issue@.service`,
		`installing_dependencies`,
		`dependencies_ready`,
		`set-credentials --username "$admin_username" --password-stdin`,
		`admin_username="${JUI_ADMIN_USERNAME:-admin}"`,
		`admin_password="${JUI_ADMIN_PASSWORD:-admin}"`,
		`ask_yes_no "$(i18n confirm_admin_password "$admin_password")" yes`,
		`ask_yes_no "$(i18n confirm_bbr "$bbr_state_label")" yes`,
		`JUI_ENABLE_BBR`,
		`net.core.default_qdisc = fq`,
		`net.ipv4.tcp_congestion_control = bbr`,
		`/etc/sysctl.d/99-j-ui-bbr.conf`,
		`sysctl -n net.ipv4.tcp_available_congestion_control`,
		`bbr_live_changed=1`,
		`ask_yes_no "$(i18n confirm_preserve_data)" yes`,
		`JUI_PRESERVE_DATA`,
		`/usr/local/bin/j-ui cleanup-firewall`,
		`rm -rf -- /etc/j-ui /var/lib/j-ui`,
		`set-language "$language"`,
		`configure-install --language "$language"`,
		`JUI_TLS_CERTIFICATE_PATH=${panel_certificate_path}`,
		`install -m 0755 "${temporary_directory}/scripts/argo.sh" /usr/local/lib/j-ui/argo.sh`,
	} {
		if !bytes.Contains(content, []byte(expected)) {
			t.Fatalf("installer node start port behavior missing %q", expected)
		}
	}
	if bytes.Contains(content, []byte(`get-public-host`)) {
		t.Fatal("installer must not reuse a persisted public host as the default; detect the current IPv4 address")
	}
	if bytes.Contains(content, []byte(`sing-box-1.13.12`)) {
		t.Fatal("installer retained the old sing-box version")
	}
	if bytes.Contains(content, []byte(`confirm_argo`)) {
		t.Fatal("initial installation must configure Argo from the management menu, not the base profile wizard")
	}
	if bytes.Contains(content, []byte(`jui-$(openssl rand`)) ||
		bytes.Contains(content, []byte(`admin_password="$(openssl rand`)) {
		t.Fatal("installer must use the explicit admin/admin default instead of printing generated credentials")
	}
	rollbackCopy := bytes.Index(content, []byte(`cp -a -- "$tree" "$rollback_tree"`))
	cleanData := bytes.Index(content, []byte(`rm -rf -- /etc/j-ui /var/lib/j-ui`))
	if rollbackCopy < 0 || cleanData < 0 || rollbackCopy >= cleanData {
		t.Fatal("clean installation must snapshot existing data before deleting it")
	}
	dependencies := bytes.Index(content, []byte(`i18n installing_dependencies`))
	profile := bytes.Index(content, []byte("\nrender_profile_header\n"))
	if dependencies < 0 || profile < 0 || dependencies >= profile {
		t.Fatal("system dependencies and release packages must be prepared before the profile wizard")
	}
}

func TestManagementMenuProvidesLifecycleAndRecoveryActions(t *testing.T) {
	content, err := os.ReadFile("manage.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`render_banner()`,
		`render_action_header "$(action_title "$action")"`,
		`blue=$'\033[38;5;39m' green=$'\033[32m'`,
		`printf '%s%s%s' "$green" "$(t running)" "$reset"`,
		`"$jui_binary" start`,
		`"$jui_binary" stop`,
		`"$jui_binary" restart`,
		`"$jui_binary" settings`,
		`replace_credentials`,
		`set-credentials --username "$new_username" --password-stdin`,
		`"$jui_binary" backup`,
		`"$jui_binary" restore "$backup_path"`,
		`"$jui_binary" update`,
		`"$jui_binary" enable`,
		`"$jui_binary" disable`,
		`"$jui_binary" uninstall`,
		`"$jui_binary" ssl`,
		`"$jui_binary" argo`,
	} {
		if !bytes.Contains(content, []byte(expected)) {
			t.Fatalf("management action missing %q", expected)
		}
	}
}

func TestArgoWizardAutomaticallyCreatesFixedTunnelAndVerifiesIt(t *testing.T) {
	content, err := os.ReadFile("argo.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`Cloudflare API Token`,
		`/cfd_tunnel`,
		`/configurations`,
		`/dns_records`,
		`http://127.0.0.1:${origin_port}`,
		`--token-file /etc/j-ui/cloudflared.token`,
		`install -m 0600 "$temporary_directory/cloudflared.token" /etc/j-ui/cloudflared.token`,
		`chmod 0700 "$temporary_directory"`,
		`DELETE "/accounts/${new_account_id}/cfd_tunnel/${new_tunnel_id}?cascade=true"`,
		`/usr/local/bin/j-ui configure-argo --domain "$domain" --origin-port "$origin_port"`,
		`/etc/j-ui/argo-profile.json`,
		`cloudflared-managed-by-jui`,
		`trap cleanup EXIT`,
	} {
		if !bytes.Contains(content, []byte(expected)) {
			t.Fatalf("Argo wizard behavior missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		`trycloudflare.com`,
		`Tunnel Token（输入不可见）`,
		`cloudflared service install "$token"`,
		`echo "$api_token"`,
		`echo "$tunnel_token"`,
	} {
		if bytes.Contains(content, []byte(forbidden)) {
			t.Fatalf("Argo wizard retained unsupported setup path %q", forbidden)
		}
	}
}

func TestArgoTunnelTokenValidationAcceptsStandardBase64(t *testing.T) {
	content, err := os.ReadFile("argo.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := extractBashFunction(t, string(content), "valid_tunnel_token")
	payload := `{"a":"0123456789abcdef0123456789abcdef","s":"+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/8=","t":"f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"}`
	token := base64.StdEncoding.EncodeToString([]byte(payload))
	if !strings.ContainsAny(token, "+/=") {
		t.Fatalf("fixture must exercise standard Base64 characters: %q", token)
	}

	command := exec.Command("bash", "-c", function+"\nvalid_tunnel_token \"$1\"", "argo-token-test", token)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("valid Cloudflare token rejected: %v\n%s", runErr, output)
	}

	command = exec.Command("bash", "-c", function+"\n! valid_tunnel_token \"$1\"", "argo-token-test", "not-a-cloudflare-token")
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("malformed Cloudflare token accepted: %v\n%s", runErr, output)
	}
}

func TestArgoWizardWaitsForDNSAndAcceptsStandardBase64TunnelToken(t *testing.T) {
	root := t.TempDir()
	content, err := os.ReadFile("argo.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		"etc/j-ui", "etc/systemd/system", "run/lock", "tmp", "usr/local/bin", "fake-bin",
	} {
		if mkdirErr := os.MkdirAll(filepath.Join(root, directory), 0o700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
	}
	rewritten := string(content)
	for _, replacement := range [][2]string{
		{"/etc/j-ui", filepath.Join(root, "etc/j-ui")},
		{"/etc/systemd/system", filepath.Join(root, "etc/systemd/system")},
		{"/usr/local/bin/j-ui", filepath.Join(root, "usr/local/bin/j-ui")},
		{"/run/lock/j-ui-lifecycle.lock", filepath.Join(root, "run/lock/j-ui-lifecycle.lock")},
		{"/tmp/j-ui-argo.", filepath.Join(root, "tmp/j-ui-argo.")},
		{"if [[ ${EUID:-$(id -u)} -ne 0 ]]; then", "if false; then"},
	} {
		rewritten = strings.ReplaceAll(rewritten, replacement[0], replacement[1])
	}
	scriptPath := filepath.Join(root, "argo.sh")
	writeFixtureFile(t, scriptPath, rewritten, 0o700)

	juiLog := filepath.Join(root, "j-ui.log")
	writeFixtureFile(t, filepath.Join(root, "usr/local/bin/j-ui"), `#!/bin/sh
count=0
[ ! -r "$TEST_JUI_STATE" ] || read -r count <"$TEST_JUI_STATE"
count=$((count + 1))
printf '%s\n' "$count" >"$TEST_JUI_STATE"
if [ "$count" -le "${TEST_JUI_FAILS_BEFORE_SUCCESS:-0}" ]; then
  printf '%s\n' 'Cloudflare Tunnel verification failed: domain not resolved yet' >&2
  exit 1
fi
printf '%s\n' "$*" >"$TEST_JUI_LOG"
`, 0o755)
	fakeBin := filepath.Join(root, "fake-bin")
	writeFixtureFile(t, filepath.Join(fakeBin, "cloudflared"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFixtureFile(t, filepath.Join(fakeBin, "sleep"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFixtureFile(t, filepath.Join(fakeBin, "systemctl"), `#!/bin/sh
case "${1:-}" in
  is-active|is-enabled|cat) exit 1 ;;
  *) exit 0 ;;
esac
`, 0o755)
	writeFixtureFile(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
method=GET
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --request) method="$2"; shift 2 ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
[ -z "${TEST_CURL_LOG:-}" ] || printf '%s %s\n' "$method" "$url" >>"$TEST_CURL_LOG"
case "$method $url" in
  "GET "*"/zones?name=argo.example.com"*) printf '{"success":true,"result":[]}' ;;
  "GET "*"/zones?name=example.com"*) printf '{"success":true,"result":[{"id":"11111111111111111111111111111111","account":{"id":"22222222222222222222222222222222"}}]}' ;;
  "POST "*"/cfd_tunnel") printf '{"success":true,"result":{"id":"33333333-3333-4333-8333-333333333333"}}' ;;
  "GET "*"/cfd_tunnel/33333333-3333-4333-8333-333333333333/token") printf '{"success":true,"result":"%s"}' "$TEST_TUNNEL_TOKEN" ;;
  "PUT "*"/configurations") printf '{"success":true,"result":{}}' ;;
  "GET "*"/dns_records?name=argo.example.com"*) printf '{"success":true,"result":[]}' ;;
  "POST "*"/dns_records") printf '{"success":true,"result":{"id":"44444444444444444444444444444444"}}' ;;
  *) printf '{"success":true,"result":{}}' ;;
esac
`, 0o755)

	payload := `{"a":"0123456789abcdef0123456789abcdef","s":"+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/8=","t":"33333333-3333-4333-8333-333333333333"}`
	token := base64.StdEncoding.EncodeToString([]byte(payload))
	curlLog := filepath.Join(root, "curl.log")
	commandEnvironment := func(failures string) []string {
		return append(os.Environ(),
			"JUI_LANGUAGE=en",
			"PATH="+fakeBin+":"+os.Getenv("PATH"),
			"TEST_JUI_LOG="+juiLog,
			"TEST_JUI_STATE="+filepath.Join(root, "j-ui.state"),
			"TEST_JUI_FAILS_BEFORE_SUCCESS="+failures,
			"TEST_TUNNEL_TOKEN="+token,
			"TEST_CURL_LOG="+curlLog,
		)
	}
	command := exec.Command("bash", scriptPath)
	command.Stdin = strings.NewReader("argo.example.com\n2080\nabcdefghijklmnopqrstuvwxyz123456\n")
	command.Env = commandEnvironment("2")
	output, runErr := command.CombinedOutput()
	if runErr != nil {
		t.Fatalf("Argo wizard failed with a valid standard Base64 token: %v\n%s", runErr, output)
	}
	if !bytes.Contains(output, []byte("Fixed-domain Argo setup is complete")) {
		t.Fatalf("Argo success message missing\n%s", output)
	}
	storedToken, readErr := os.ReadFile(filepath.Join(root, "etc/j-ui/cloudflared.token"))
	if readErr != nil || strings.TrimSpace(string(storedToken)) != token {
		t.Fatalf("stored tunnel token mismatch: err=%v", readErr)
	}
	info, statErr := os.Stat(filepath.Join(root, "etc/j-ui/cloudflared.token"))
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("tunnel token permissions=%v", info.Mode().Perm())
	}
	serviceUnit, readErr := os.ReadFile(filepath.Join(root, "etc/systemd/system/cloudflared.service"))
	if readErr != nil || !bytes.Contains(serviceUnit, []byte("ExecStart="+filepath.Join(fakeBin, "cloudflared")+" --no-autoupdate")) {
		t.Fatalf("cloudflared service executable=%q err=%v", serviceUnit, readErr)
	}
	juiCall, readErr := os.ReadFile(juiLog)
	if readErr != nil || strings.TrimSpace(string(juiCall)) != "configure-argo --domain argo.example.com --origin-port 2080" {
		t.Fatalf("configure-argo call=%q err=%v", juiCall, readErr)
	}
	verifyCalls, readErr := os.ReadFile(filepath.Join(root, "j-ui.state"))
	if readErr != nil || strings.TrimSpace(string(verifyCalls)) != "3" {
		t.Fatalf("configure-argo attempts=%q err=%v", verifyCalls, readErr)
	}

	writeFixtureFile(t, filepath.Join(root, "j-ui.state"), "0\n", 0o600)
	writeFixtureFile(t, curlLog, "", 0o600)
	failedCommand := exec.Command("bash", scriptPath)
	failedCommand.Stdin = strings.NewReader("argo.example.com\n2080\nabcdefghijklmnopqrstuvwxyz123456\n")
	failedCommand.Env = commandEnvironment("24")
	failedOutput, failedErr := failedCommand.CombinedOutput()
	if failedErr == nil || !bytes.Contains(failedOutput, []byte("Argo setup failed")) {
		t.Fatalf("persistent DNS failure did not roll back: err=%v\n%s", failedErr, failedOutput)
	}
	rollbackRequests, readErr := os.ReadFile(curlLog)
	if readErr != nil ||
		!bytes.Contains(rollbackRequests, []byte("DELETE https://api.cloudflare.com/client/v4/zones/11111111111111111111111111111111/dns_records/44444444444444444444444444444444")) ||
		!bytes.Contains(rollbackRequests, []byte("DELETE https://api.cloudflare.com/client/v4/accounts/22222222222222222222222222222222/cfd_tunnel/33333333-3333-4333-8333-333333333333?cascade=true")) {
		t.Fatalf("Cloudflare rollback requests=%q err=%v", rollbackRequests, readErr)
	}
}

func extractBashFunction(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, name+"() {")
	if start < 0 {
		t.Fatalf("function %s not found", name)
	}
	remainder := script[start:]
	end := strings.Index(remainder, "\n}\n")
	if end < 0 {
		t.Fatalf("function %s has no closing brace", name)
	}
	return remainder[:end+2]
}
