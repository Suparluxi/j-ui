package scripts_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUpdateRollsBackFailureAfterMutationStarts(t *testing.T) {
	testUpdateRollback(t, false)
}

func TestUpdatePreservesRecoveryBundleWhenRollbackIsIncomplete(t *testing.T) {
	testUpdateRollback(t, true)
}

func TestUpdateHealthCheckSupportsLoopbackHTTPS(t *testing.T) {
	script, err := os.ReadFile("update.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(script, []byte(`for _ in {1..60}; do`)) ||
		!bytes.Contains(script, []byte(`curl --http1.1 -kfsS --max-time 2 "$health_url" >/dev/null 2>&1`)) {
		t.Fatal("updater health check must allow the public certificate on its loopback-only probe")
	}
	for _, expected := range []string{
		`readonly singbox_version="1.13.16"`,
		`"${temporary_directory}/sing-box" check -c /etc/j-ui/sing-box.json`,
		`install -m 0755 "${temporary_directory}/sing-box" /usr/local/lib/j-ui/sing-box`,
		`/usr/local/lib/j-ui/sing-box`,
		`systemctl restart j-ui-certificate-renew.timer`,
	} {
		if !bytes.Contains(script, []byte(expected)) {
			t.Fatalf("updater sing-box upgrade behavior missing %q", expected)
		}
	}
}

func TestUpdateMigratesResidentialRuntimeForLegacyUpgrades(t *testing.T) {
	updateScript, err := os.ReadFile("update.sh")
	if err != nil {
		t.Fatal(err)
	}
	serviceUnit, err := os.ReadFile(filepath.Join("..", "deploy", "j-ui.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`if [[ "${1:-}" == "--ensure-residential-runtime" ]]; then`,
		`grep -Fq 'Description=J-UI isolated residential sing-box node %i'`,
		`grep -Fq 'ExecStart=/usr/local/lib/j-ui/sing-box run -c /etc/j-ui/residential/%i.json'`,
		`systemctl daemon-reload`,
	} {
		if !bytes.Contains(updateScript, []byte(expected)) {
			t.Fatalf("legacy upgrade migration is missing %q", expected)
		}
	}
	for _, expected := range []string{
		`ExecStartPre=/usr/local/lib/j-ui/update.sh --ensure-residential-runtime`,
		`ReadWritePaths=/etc/j-ui /var/lib/j-ui /etc/systemd/system`,
	} {
		if !bytes.Contains(serviceUnit, []byte(expected)) {
			t.Fatalf("J-UI service cannot run legacy upgrade migration %q", expected)
		}
	}
}

func testUpdateRollback(t *testing.T, failRollbackCopy bool) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture archive name is amd64")
	}
	root := t.TempDir()
	script, err := os.ReadFile("update.sh")
	if err != nil {
		t.Fatal(err)
	}
	replacements := map[string]string{
		"/usr/local/bin/j-ui":                    filepath.Join(root, "usr/local/bin/j-ui"),
		"/usr/local/bin/jui":                     filepath.Join(root, "usr/local/bin/jui"),
		"/usr/local/bin/J-UI":                    filepath.Join(root, "usr/local/bin/J-UI"),
		"/usr/local/bin/J-Ui":                    filepath.Join(root, "usr/local/bin/J-Ui"),
		"/usr/local/bin/J-uI":                    filepath.Join(root, "usr/local/bin/J-uI"),
		"/usr/local/bin/J-ui":                    filepath.Join(root, "usr/local/bin/J-ui"),
		"/usr/local/bin/j-UI":                    filepath.Join(root, "usr/local/bin/j-UI"),
		"/usr/local/bin/j-Ui":                    filepath.Join(root, "usr/local/bin/j-Ui"),
		"/usr/local/bin/j-uI":                    filepath.Join(root, "usr/local/bin/j-uI"),
		"/usr/local/bin/jui-menu":                filepath.Join(root, "usr/local/bin/jui-menu"),
		"/etc/systemd/system":                    filepath.Join(root, "etc/systemd/system"),
		"/usr/local/lib/j-ui":                    filepath.Join(root, "usr/local/lib/j-ui"),
		"/var/backups/j-ui":                      filepath.Join(root, "var/backups/j-ui"),
		"/etc/j-ui":                              filepath.Join(root, "etc/j-ui"),
		"/var/lib/j-ui":                          filepath.Join(root, "var/lib/j-ui"),
		"/run/lock/j-ui-lifecycle.lock":          filepath.Join(root, "run/lock/j-ui-lifecycle.lock"),
		"if [[ ${EUID:-$(id -u)} -ne 0 ]]; then": "if false; then",
	}
	rewritten := string(script)
	for old, replacement := range replacements {
		rewritten = strings.ReplaceAll(rewritten, old, replacement)
	}
	scriptPath := filepath.Join(root, "update.sh")
	if err := os.WriteFile(scriptPath, []byte(rewritten), 0o700); err != nil {
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
		filepath.Join(root, "etc/systemd/system/j-ui.service"),
		filepath.Join(root, "etc/systemd/system/j-ui-update.service"),
		filepath.Join(root, "etc/systemd/system/j-ui-sing-box.service"),
		filepath.Join(root, "etc/systemd/system/j-ui-residential@.service"),
		filepath.Join(root, "etc/systemd/system/j-ui-certificate-renew.service"),
		filepath.Join(root, "etc/systemd/system/j-ui-certificate-renew.timer"),
		filepath.Join(root, "usr/local/lib/j-ui/update.sh"),
		filepath.Join(root, "usr/local/lib/j-ui/uninstall.sh"),
		filepath.Join(root, "usr/local/lib/j-ui/manage.sh"),
		filepath.Join(root, "usr/local/lib/j-ui/ssl.sh"),
	}
	logPath := filepath.Join(root, "old-binary.log")
	oldBinary := fmt.Sprintf(`#!/usr/bin/env bash
set -eu
case "${1:-}" in
  backup) mkdir -p "$(dirname "$2")"; printf 'backup' >"$2" ;;
  cleanup-firewall) printf 'cleanup\n' >>%q ;;
  internal-update-result) printf 'event %%s\n' "$2" >>%q ;;
esac
`, logPath, logPath)
	for index, target := range managed {
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		content := []byte(fmt.Sprintf("old-%d", index))
		mode := os.FileMode(0o600)
		if index == 0 {
			content = []byte(oldBinary)
			mode = 0o700
		}
		if err := os.WriteFile(target, content, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "run/lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldContents := make(map[string][]byte)
	for _, target := range managed {
		content, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		oldContents[target] = content
	}
	for _, treeFile := range []string{
		filepath.Join(root, "etc/j-ui/j-ui.env"),
		filepath.Join(root, "var/lib/j-ui/j-ui.db"),
	} {
		writeFixtureFile(t, treeFile, "old-tree\n", 0o600)
		oldContents[treeFile] = []byte("old-tree\n")
	}

	release := filepath.Join(root, "release")
	writeFixtureFile(t, filepath.Join(release, "j-ui"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFixtureFile(t, filepath.Join(release, "sing-box"), "#!/bin/sh\nif [ \"${1:-}\" = version ]; then echo 'sing-box version 1.13.16'; fi\nexit 0\n", 0o755)
	for _, path := range []string{
		"deploy/j-ui.service", "deploy/j-ui-update.service", "deploy/j-ui-sing-box.service",
		"deploy/j-ui-residential@.service",
		"deploy/j-ui-certificate-renew.service", "deploy/j-ui-certificate-renew.timer",
		"deploy/j-ui-certificate-issue@.service",
		"scripts/update.sh", "scripts/uninstall.sh", "scripts/manage.sh", "scripts/ssl.sh", "scripts/argo.sh",
	} {
		writeFixtureFile(t, filepath.Join(release, path), "new-"+path+"\n", 0o755)
	}
	archiveName := "j-ui_0.1.0_linux_amd64.tar.gz"
	archivePath := filepath.Join(root, archiveName)
	createArchive(t, archivePath, release)
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	checksumsPath := filepath.Join(root, "checksums.txt")
	checksum := fmt.Sprintf("%x  %s\n", sha256.Sum256(archiveBytes), archiveName)
	if err := os.WriteFile(checksumsPath, []byte(checksum), 0o600); err != nil {
		t.Fatal(err)
	}

	fakeBin := filepath.Join(root, "fake-bin")
	if err := os.MkdirAll(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
set -eu
case "$2" in
  *checksums.txt) cp "$TEST_CHECKSUMS" "$4" ;;
  *) cp "$TEST_ARCHIVE" "$4" ;;
esac
`, 0o755)
	writeFixtureFile(t, filepath.Join(fakeBin, "systemctl"), "#!/bin/sh\nexit 0\n", 0o755)
	if failRollbackCopy {
		writeFixtureFile(t, filepath.Join(fakeBin, "cp"), `#!/bin/sh
set -eu
source_path=""
for argument in "$@"; do
  case "$argument" in -*) ;; *) source_path="$argument"; break ;; esac
done
case "$source_path" in
  */managed*/etc/systemd/system/j-ui.service) exit 74 ;;
esac
exec /bin/cp "$@"
`, 0o755)
	}
	failTarget := filepath.Join(root, "etc/systemd/system/j-ui.service")
	writeFixtureFile(t, filepath.Join(fakeBin, "install"), `#!/bin/sh
set -eu
last=""
for argument in "$@"; do last="$argument"; done
if [ "$last" = "$TEST_FAIL_TARGET" ]; then exit 73; fi
if [ "$last" = "$TEST_BINARY_TARGET" ]; then
  /usr/bin/install "$@"
  printf 'newer-schema-tree\n' >"$TEST_DATABASE_PATH"
  exit 0
fi
exec /usr/bin/install "$@"
`, 0o755)

	command := exec.Command("bash", scriptPath)
	command.Env = append(os.Environ(),
		"JUI_VERSION=0.1.0",
		"TEST_ARCHIVE="+archivePath,
		"TEST_CHECKSUMS="+checksumsPath,
		"TEST_FAIL_TARGET="+failTarget,
		"TEST_BINARY_TARGET="+filepath.Join(root, "usr/local/bin/j-ui.new"),
		"TEST_DATABASE_PATH="+filepath.Join(root, "var/lib/j-ui/j-ui.db"),
		"PATH="+fakeBin+":"+os.Getenv("PATH"),
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("update unexpectedly succeeded\n%s", output)
	}
	if failRollbackCopy {
		if !bytes.Contains(output, []byte("automatic rollback both failed; recovery bundle:")) {
			t.Fatalf("incomplete rollback warning missing\n%s", output)
		}
		recoveryBundles, globErr := filepath.Glob(
			filepath.Join(root, "var/backups/j-ui/recovery-update-*"),
		)
		if globErr != nil || len(recoveryBundles) != 1 {
			t.Fatalf("recovery bundles=%#v err=%v\n%s", recoveryBundles, globErr, output)
		}
		if _, statErr := os.Stat(filepath.Join(recoveryBundles[0], "logical-backup.tar.gz")); statErr != nil {
			t.Fatalf("logical backup missing from recovery bundle: %v", statErr)
		}
	} else if !bytes.Contains(output, []byte("previous binary, units, scripts, database, and configuration were restored")) {
		t.Fatalf("rollback confirmation missing\n%s", output)
	}
	for _, target := range managed {
		if failRollbackCopy && target == failTarget {
			continue
		}
		content, readErr := os.ReadFile(target)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(content, oldContents[target]) {
			t.Fatalf("%s was not restored", target)
		}
	}
	for target, expected := range oldContents {
		if failRollbackCopy && target == failTarget {
			continue
		}
		content, readErr := os.ReadFile(target)
		if readErr != nil || !bytes.Equal(content, expected) {
			t.Fatalf("rollback content %s=%q err=%v", target, content, readErr)
		}
	}
	logContent, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(logContent), "event") {
		t.Fatalf("rollback restore log=%q err=%v", logContent, err)
	}
}

func writeFixtureFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func createArchive(t *testing.T, destination, root string) {
	t.Helper()
	file, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relative)
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err == nil {
		err = tarWriter.Close()
	}
	if err == nil {
		err = gzipWriter.Close()
	}
	if err == nil {
		err = file.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}
