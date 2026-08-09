package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type scriptedRunner struct {
	run func(string, ...string) ([]byte, error)
}

func (r scriptedRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	return r.run(name, args...)
}

func TestEnsureFailsWhenNoFirewallBackendExists(t *testing.T) {
	system := System{
		Runner: scriptedRunner{run: func(string, ...string) ([]byte, error) {
			return nil, errors.New("not running")
		}},
		Lookup: func(string) (string, error) {
			return "", errors.New("not found")
		},
	}
	_, err := system.Ensure(context.Background(), "tcp", 443)
	if err == nil || !strings.Contains(err.Error(), "no active firewalld") {
		t.Fatalf("Ensure error = %v", err)
	}
}

func TestNftSetupFailureIsReturned(t *testing.T) {
	system := System{
		Runner: scriptedRunner{run: func(_ string, args ...string) ([]byte, error) {
			if strings.Join(args, " ") == "-j -a list ruleset" {
				return []byte(`{"nftables":[]}`), nil
			}
			if len(args) >= 2 && args[0] == "add" && args[1] == "table" {
				return []byte("permission denied"), errors.New("exit status 1")
			}
			return nil, errors.New("missing")
		}},
		Lookup: func(name string) (string, error) {
			if name == "nft" {
				return "/usr/sbin/nft", nil
			}
			return "", errors.New("not found")
		},
	}
	_, err := system.Ensure(context.Background(), "udp", 443)
	if err == nil || !strings.Contains(err.Error(), "create nftables table") {
		t.Fatalf("Ensure error = %v", err)
	}
}

func TestNftInsertsRuleIntoPolicyDropInputChain(t *testing.T) {
	var commands []string
	system := System{
		Runner: scriptedRunner{run: func(name string, args ...string) ([]byte, error) {
			command := name + " " + strings.Join(args, " ")
			commands = append(commands, command)
			if strings.Join(args, " ") == "-j -a list ruleset" {
				return []byte(`{"nftables":[
					{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},
					{"chain":{"family":"inet","table":"jui","name":"input","type":"filter","hook":"input","prio":-5,"policy":"accept"}},
					{"rule":{"family":"inet","table":"jui","chain":"input","handle":8,"comment":"jui-tcp-8080"}}
				]}`), nil
			}
			return nil, nil
		}},
		Lookup: func(name string) (string, error) {
			if name == "nft" {
				return "/usr/sbin/nft", nil
			}
			return "", errors.New("not found")
		},
	}
	result, err := system.Ensure(context.Background(), "tcp", 8080)
	if err != nil {
		t.Fatal(err)
	}
	if result.Ownership != Owned || result.Backend != BackendNFTables {
		t.Fatalf("result = %#v", result)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "nft insert rule inet filter input tcp dport 8080 accept comment jui-tcp-8080") {
		t.Fatalf("effective policy-drop rule missing:\n%s", joined)
	}
	if strings.Contains(joined, "nft add table") {
		t.Fatalf("legacy table was modified:\n%s", joined)
	}
}

func TestNftDoesNotDuplicateRuleInPolicyDropInputChain(t *testing.T) {
	var commands []string
	system := System{
		Runner: scriptedRunner{run: func(name string, args ...string) ([]byte, error) {
			commands = append(commands, name+" "+strings.Join(args, " "))
			if strings.Join(args, " ") == "-j -a list ruleset" {
				return []byte(`{"nftables":[
					{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"drop"}},
					{"rule":{"family":"inet","table":"filter","chain":"input","handle":17,"comment":"jui-tcp-8080"}}
				]}`), nil
			}
			return nil, nil
		}},
		Lookup: func(name string) (string, error) {
			if name == "nft" {
				return "/usr/sbin/nft", nil
			}
			return "", errors.New("not found")
		},
	}
	if _, err := system.Ensure(context.Background(), "tcp", 8080); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0] != "nft -j -a list ruleset" {
		t.Fatalf("commands = %#v", commands)
	}
}

func TestNftCloseDeletesOwnedRulesFromEveryChain(t *testing.T) {
	var deleteCommand string
	system := System{
		Runner: scriptedRunner{run: func(name string, args ...string) ([]byte, error) {
			if strings.Join(args, " ") == "-j -a list ruleset" {
				return []byte(`{"nftables":[
					{"rule":{"family":"inet","table":"filter","chain":"input","handle":17,"comment":"jui-tcp-8080"}},
					{"rule":{"family":"inet","table":"jui","chain":"input","handle":8,"comment":"jui-tcp-8080"}},
					{"rule":{"family":"inet","table":"filter","chain":"input","handle":18,"comment":"unrelated"}}
				]}`), nil
			}
			deleteCommand = name + " " + strings.Join(args, " ")
			return nil, nil
		}},
		Lookup: func(name string) (string, error) {
			if name == "nft" {
				return "/usr/sbin/nft", nil
			}
			return "", errors.New("not found")
		},
	}
	if err := system.Close(context.Background(), "tcp", 8080, BackendNFTables); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(deleteCommand, "delete rule inet filter input handle 17 ; delete rule inet jui input handle 8") ||
		strings.Contains(deleteCommand, "handle 18") {
		t.Fatalf("delete command = %q", deleteCommand)
	}
}

func TestRejectsInvalidRule(t *testing.T) {
	system := System{}
	if _, err := system.Ensure(context.Background(), "sctp", 443); err == nil {
		t.Fatal("invalid protocol was accepted")
	}
	if err := system.Close(context.Background(), "tcp", 0, BackendNFTables); err == nil {
		t.Fatal("invalid port was accepted")
	}
}

func TestUFWOnlyRemovesRulesOwnedByJUI(t *testing.T) {
	var commands []string
	system := System{
		Runner: scriptedRunner{run: func(name string, args ...string) ([]byte, error) {
			commands = append(commands, name+" "+strings.Join(args, " "))
			switch strings.Join(args, " ") {
			case "is-active --quiet firewalld":
				return nil, errors.New("inactive")
			case "status":
				return []byte("Status: active\n443/tcp ALLOW Anywhere\n443/tcp (v6) ALLOW Anywhere (v6)\n"), nil
			case "status numbered":
				return []byte("Status: active\n[ 1] 443/tcp ALLOW IN Anywhere\n[ 2] 443/tcp ALLOW IN Anywhere # jui-tcp-443\n[ 3] 443/tcp (v6) ALLOW IN Anywhere (v6) # jui-tcp-443\n"), nil
			default:
				return nil, nil
			}
		}},
		Lookup: func(name string) (string, error) {
			if name == "ufw" || name == "firewall-cmd" {
				return "/usr/sbin/" + name, nil
			}
			return "", errors.New("not found")
		},
	}
	ownership, err := system.Ensure(context.Background(), "tcp", 443)
	if err != nil {
		t.Fatal(err)
	}
	if ownership.Ownership != Borrowed || ownership.Backend != BackendUFW {
		t.Fatalf("result = %#v, want borrowed UFW", ownership)
	}
	if err := system.Close(context.Background(), "tcp", 443, BackendUFW); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	if strings.Contains(joined, "ufw allow 443/tcp comment jui-tcp-443") {
		t.Fatalf("borrowed rule was overwritten:\n%s", joined)
	}
	if !strings.Contains(joined, "ufw --force delete 3") ||
		!strings.Contains(joined, "ufw --force delete 2") {
		t.Fatalf("owned delete commands missing:\n%s", joined)
	}
	if strings.Contains(joined, "delete allow") || strings.Contains(joined, "--force delete 1") {
		t.Fatalf("generic rule was targeted:\n%s", joined)
	}
}

func TestUFWRejectsRestrictedOrDenyRulesInsteadOfBorrowing(t *testing.T) {
	for _, status := range []string{
		"Status: active\n443/tcp DENY Anywhere\n443/tcp (v6) DENY Anywhere (v6)\n",
		"Status: active\n443/tcp ALLOW 10.0.0.0/8\n443/tcp (v6) ALLOW Anywhere (v6)\n",
	} {
		system := System{
			Runner: scriptedRunner{run: func(name string, args ...string) ([]byte, error) {
				if name == "systemctl" {
					return nil, errors.New("inactive")
				}
				if name == "ufw" && strings.Join(args, " ") == "status" {
					return []byte(status), nil
				}
				return nil, nil
			}},
			Lookup: func(name string) (string, error) {
				if name == "ufw" || name == "firewall-cmd" {
					return "/usr/sbin/" + name, nil
				}
				return "", errors.New("not found")
			},
		}
		if _, err := system.Ensure(context.Background(), "tcp", 443); err == nil ||
			!strings.Contains(err.Error(), "refusing to overwrite") {
			t.Fatalf("Ensure with status %q returned %v", status, err)
		}
	}
}

func TestUFWMarkerMatchingDoesNotConfusePortPrefixes(t *testing.T) {
	var commands []string
	system := System{
		Runner: scriptedRunner{run: func(name string, args ...string) ([]byte, error) {
			commands = append(commands, name+" "+strings.Join(args, " "))
			if name == "systemctl" {
				return nil, errors.New("inactive")
			}
			switch strings.Join(args, " ") {
			case "status":
				return []byte("Status: active\n443/tcp ALLOW Anywhere # jui-tcp-443\n443/tcp (v6) ALLOW Anywhere (v6) # jui-tcp-443\n"), nil
			case "status numbered":
				return []byte("Status: active\n[ 1] 443/tcp ALLOW IN Anywhere # jui-tcp-443\n"), nil
			default:
				return nil, nil
			}
		}},
		Lookup: func(name string) (string, error) {
			if name == "ufw" || name == "firewall-cmd" {
				return "/usr/sbin/" + name, nil
			}
			return "", errors.New("not found")
		},
	}
	result, err := system.Ensure(context.Background(), "tcp", 44)
	if err != nil || result.Ownership != Owned {
		t.Fatalf("Ensure 44 = %#v, %v", result, err)
	}
	if err := system.Close(context.Background(), "tcp", 44, BackendUFW); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "ufw allow 44/tcp comment jui-tcp-44") ||
		strings.Contains(joined, "ufw --force delete 1") {
		t.Fatalf("prefix marker collision:\n%s", joined)
	}
}

func TestFirewalldUsesDedicatedPolicy(t *testing.T) {
	var commands []string
	system := System{
		Runner: scriptedRunner{run: func(name string, args ...string) ([]byte, error) {
			command := name + " " + strings.Join(args, " ")
			commands = append(commands, command)
			if name == "systemctl" {
				return nil, nil
			}
			switch {
			case strings.Contains(command, "--get-policies"):
				return []byte("public"), nil
			case strings.Contains(command, "--query-ingress-zone"),
				strings.Contains(command, "--query-egress-zone"):
				return nil, errors.New("not configured")
			case strings.Contains(command, "--query-port"):
				return nil, errors.New("not present")
			}
			return nil, nil
		}},
		Lookup: func(name string) (string, error) {
			if name == "firewall-cmd" {
				return "/usr/bin/firewall-cmd", nil
			}
			return "", errors.New("not found")
		},
	}
	if _, err := system.Ensure(context.Background(), "udp", 8443); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "--new-policy=jui") ||
		!strings.Contains(joined, "--policy=jui --add-ingress-zone=ANY") ||
		!strings.Contains(joined, "--policy=jui --add-egress-zone=HOST") ||
		!strings.Contains(joined, "--policy=jui --add-port=8443/udp") ||
		strings.Contains(joined, "--direct") {
		t.Fatalf("unexpected firewalld commands:\n%s", joined)
	}
}
