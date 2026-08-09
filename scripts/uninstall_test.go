package scripts_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallCanKeepOrPurgeData(t *testing.T) {
	for _, test := range []struct {
		name     string
		keepData string
		wantKeep bool
		wantText string
	}{
		{name: "keep", keepData: "y", wantKeep: true, wantText: "Data remains"},
		{name: "purge", keepData: "n", wantKeep: false, wantText: "database, keys, runtime data, and backups were deleted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			script, err := os.ReadFile("uninstall.sh")
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
				"/usr/local/lib/j-ui":                    filepath.Join(root, "usr/local/lib/j-ui"),
				"/etc/systemd/system":                    filepath.Join(root, "etc/systemd/system"),
				"/var/lib/j-ui":                          filepath.Join(root, "var/lib/j-ui"),
				"/etc/j-ui":                              filepath.Join(root, "etc/j-ui"),
				"/var/backups/j-ui":                      filepath.Join(root, "var/backups/j-ui"),
				"/var/log/j-ui":                          filepath.Join(root, "var/log/j-ui"),
				"/run/j-ui":                              filepath.Join(root, "run/j-ui"),
				"/run/lock/j-ui-lifecycle.lock":          filepath.Join(root, "run/lock/j-ui-lifecycle.lock"),
				"/opt/j-ui/certbot":                      filepath.Join(root, "opt/j-ui/certbot"),
				"if [[ ${EUID:-$(id -u)} -ne 0 ]]; then": "if false; then",
			}
			rewritten := string(script)
			for old, replacement := range replacements {
				rewritten = strings.ReplaceAll(rewritten, old, replacement)
			}
			scriptPath := filepath.Join(root, "uninstall.sh")
			if err := os.WriteFile(scriptPath, []byte(rewritten), 0o700); err != nil {
				t.Fatal(err)
			}

			for _, path := range []string{
				filepath.Join(root, "etc/j-ui/j-ui.env"),
				filepath.Join(root, "var/lib/j-ui/data.db"),
				filepath.Join(root, "var/backups/j-ui/backup.tar.gz"),
				filepath.Join(root, "var/log/j-ui/panel.log"),
				filepath.Join(root, "run/j-ui/panel.pid"),
				filepath.Join(root, "usr/local/lib/j-ui/sing-box"),
				filepath.Join(root, "usr/local/bin/j-ui"),
				filepath.Join(root, "etc/systemd/system/j-ui.service"),
			} {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("fixture\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "etc/j-ui/j-ui.env"), []byte("JUI_LANGUAGE=en\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(root, "usr/local/bin/j-ui"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, "run/lock"), 0o700); err != nil {
				t.Fatal(err)
			}

			fakeBin := filepath.Join(root, "fake-bin")
			if err := os.MkdirAll(fakeBin, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, command := range []string{"systemctl", "ip", "nft"} {
				writeFixtureFile(t, filepath.Join(fakeBin, command), "#!/bin/sh\nexit 0\n", 0o755)
			}
			writeFixtureFile(t, filepath.Join(root, "usr/local/bin/j-ui"), "#!/bin/sh\n[ \"${1:-}\" = cleanup-firewall ] && exit 0\nexit 0\n", 0o755)

			command := exec.Command("bash", scriptPath)
			command.Stdin = strings.NewReader("y\n" + test.keepData + "\n")
			command.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"))
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("uninstall failed: %v\n%s", err, output)
			}
			if !bytes.Contains(output, []byte(test.wantText)) {
				t.Fatalf("confirmation result missing %q:\n%s", test.wantText, output)
			}

			for _, path := range []string{
				filepath.Join(root, "usr/local/lib/j-ui"),
				filepath.Join(root, "usr/local/bin/j-ui"),
				filepath.Join(root, "usr/local/bin/jui"),
				filepath.Join(root, "usr/local/bin/J-UI"),
				filepath.Join(root, "usr/local/bin/J-Ui"),
				filepath.Join(root, "usr/local/bin/J-uI"),
				filepath.Join(root, "usr/local/bin/J-ui"),
				filepath.Join(root, "usr/local/bin/j-UI"),
				filepath.Join(root, "usr/local/bin/j-Ui"),
				filepath.Join(root, "usr/local/bin/j-uI"),
				filepath.Join(root, "etc/systemd/system/j-ui.service"),
			} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("managed program path still exists: %s (err=%v)", path, err)
				}
			}
			for _, path := range []string{
				filepath.Join(root, "var/lib/j-ui"),
				filepath.Join(root, "etc/j-ui"),
				filepath.Join(root, "var/backups/j-ui"),
			} {
				_, err := os.Stat(path)
				if test.wantKeep {
					if err != nil {
						t.Fatalf("data path was not kept: %s: %v", path, err)
					}
				} else if !os.IsNotExist(err) {
					t.Fatalf("data path was not purged: %s (err=%v)", path, err)
				}
			}
		})
	}
}
