package scripts_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestReleaseVersionExtraction(t *testing.T) {
	const pipeline = `jq -r '.tag_name // empty' | sed -n 's/^v//p' | head -n 1`
	for _, path := range []string{"install.sh", "update.sh"} {
		script, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(script), pipeline) {
			t.Fatalf("%s does not use the validated release-version parser", path)
		}
	}

	command := exec.Command("bash", "-c", pipeline)
	command.Stdin = strings.NewReader(`{"tag_name":"v1.0.0"}`)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("release-version parser failed: %v: %s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != "1.0.0" {
		t.Fatalf("release-version parser returned %q", got)
	}
}
