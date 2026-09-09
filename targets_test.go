package divert

import (
	"net/netip"
	"testing"
)

func TestTargetRules(t *testing.T) {
	rules := []TargetRule{{IPs: []string{"192.0.2.129/24", "2001:db8:1::/48"}, Ports: []string{"3724", "8000-8100"}}, {IPs: []string{"198.51.100.9"}, Ports: []string{"443"}}}
	set, err := compileTargets(rules)
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]bool{
		"192.0.2.1:3724": true, "192.0.2.255:8100": true, "192.0.3.1:3724": false, "192.0.2.1:443": false,
		"198.51.100.9:443": true, "198.51.100.9:3724": false, "[2001:db8:1::1]:8000": true, "[2001:db8:2::1]:8000": false,
	} {
		if got := set.matches(netip.MustParseAddrPort(target)); got != want {
			t.Fatalf("%s: got %v, want %v", target, got, want)
		}
	}
	for _, rules := range [][]TargetRule{nil, {{}}, {{IPs: []string{"0.0.0.0/0", "::/0"}, Ports: []string{"1-65535"}}}} {
		set, err := compileTargets(rules)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"192.0.2.1:1", "[2001:db8::1]:65535"} {
			if !set.matches(netip.MustParseAddrPort(target)) {
				t.Fatal(target)
			}
		}
	}
}

func TestInvalidTargets(t *testing.T) {
	for _, ip := range []string{"example.com", "*", "192.0.2.1/33", "2001:db8::/129", "fe80::1%eth0", "::ffff:192.0.2.1", "1.2.3.4 or true", ""} {
		if _, err := compileTargets([]TargetRule{{IPs: []string{ip}}}); err == nil {
			t.Fatalf("accepted IP %q", ip)
		}
	}
	for _, port := range []string{"0", "65536", "-1", "1-0", "80-79", "80-81-82", "80 or true", " 80", "+80", "*", ""} {
		if _, err := compileTargets([]TargetRule{{Ports: []string{port}}}); err == nil {
			t.Fatalf("accepted port %q", port)
		}
	}
	many := make([]string, 65)
	for i := range many {
		many[i] = "3724"
	}
	if _, err := compileTargets([]TargetRule{{Ports: many}}); err == nil {
		t.Fatal("unbounded selector count")
	}
	if _, err := compileTargets(make([]TargetRule, 33)); err == nil {
		t.Fatal("unbounded rule count")
	}
}

func TestTargetConfigSnapshot(t *testing.T) {
	cfg := Config{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:1080", Targets: []TargetRule{{IPs: []string{"192.0.2.0/24"}, Ports: []string{"3724"}}}}
	p, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].IPs[0] = "198.51.100.0/24"
	cfg.Targets[0].Ports[0] = "443"
	cfg.Targets[0] = TargetRule{}
	if p.cfg.Targets[0].IPs[0] != "192.0.2.0/24" || p.cfg.Targets[0].Ports[0] != "3724" || !p.cfg.targets.matches(netip.MustParseAddrPort("192.0.2.1:3724")) {
		t.Fatal("mutable target configuration retained")
	}
}
