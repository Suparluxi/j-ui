package scripts_test

import (
	"os"
	"strings"
	"testing"
)

func TestCertificateRenewalUsesRecurringCalendarSchedule(t *testing.T) {
	content, err := os.ReadFile("../deploy/j-ui-certificate-renew.timer")
	if err != nil {
		t.Fatal(err)
	}
	timer := string(content)
	for _, expected := range []string{
		"OnCalendar=*-*-* 00,12:00:00",
		"RandomizedDelaySec=30min",
		"Persistent=true",
	} {
		if !strings.Contains(timer, expected) {
			t.Fatalf("certificate renewal timer missing %q", expected)
		}
	}
	if strings.Contains(timer, "OnUnitActiveSec=") {
		t.Fatal("certificate renewal timer must not depend on prior service activation")
	}
}
