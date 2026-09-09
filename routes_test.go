package divert

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func noRouteIO(context.Context, *net.TCPConn, netip.AddrPort) error { return nil }

func TestRoutesRejectAmbiguityAndSnapshot(t *testing.T) {
	routes := []Route{
		{Name: "a", Apps: []string{`C:\Games\A\Game.exe`}, Targets: []TargetRule{{Ports: []string{"3724"}}}, Handler: noRouteIO},
		{Name: "b", Apps: []string{`C:\Games\B\Game.exe`}, Targets: []TargetRule{{Ports: []string{"8085"}}}, Handler: noRouteIO},
	}
	p, err := New(Config{}, Options{Routes: routes})
	if err != nil {
		t.Fatal(err)
	}
	routes[0].Apps[0] = "changed.exe"
	routes[0].Targets[0].Ports[0] = "443"
	routes[0].Handler = nil
	for _, tc := range []struct{ path, target, want string }{
		{`c:/games/a/GAME.EXE`, "192.0.2.1:3724", "a"},
		{`C:\Games\A\Game.exe`, "192.0.2.1:8085", ""},
		{`C:\Games\B\Game.exe`, "[2001:db8::1]:8085", "b"},
		{`C:\Games\B\Game.exe`, "[2001:db8::1]:3724", ""},
		{`C:\Games\Other\Game.exe`, "192.0.2.1:3724", ""},
	} {
		if got := p.cfg.selectRoute(tc.path, netip.MustParseAddrPort(tc.target)); got != tc.want {
			t.Fatalf("%s %s route=%q want=%q", tc.path, tc.target, got, tc.want)
		}
	}
	for _, pair := range [][2]string{{"Σ.exe", "ς.EXE"}, {"game.exe", "GAME.EXE"}, {"game.exe", `C:\Games\game.exe`}, {`C:\Games\game.exe`, "GAME.exe"}, {`C:\Games\game.exe`, `c:/games/GAME.exe`}} {
		_, err := New(Config{}, Options{Routes: []Route{{Name: "a", Apps: []string{pair[0]}, Handler: noRouteIO}, {Name: "b", Apps: []string{pair[1]}, Handler: noRouteIO}}})
		if err == nil {
			t.Fatalf("accepted overlap %v", pair)
		}
	}
	for _, rs := range [][]Route{
		{{Name: "", Apps: []string{"a.exe"}, Handler: noRouteIO}},
		{{Name: "a", Apps: []string{"a.exe"}}},
		{{Name: "a", Handler: noRouteIO}},
		{{Name: "a", Apps: []string{"a.exe"}, Handler: noRouteIO}, {Name: "a", Apps: []string{"b.exe"}, Handler: noRouteIO}},
	} {
		if _, err := New(Config{}, Options{Routes: rs}); err == nil {
			t.Fatal("accepted invalid routes")
		}
	}
	if _, err := New(Config{Apps: []string{"a.exe"}}, Options{Routes: []Route{{Name: "a", Apps: []string{"a.exe"}, Handler: noRouteIO}}}); err == nil {
		t.Fatal("accepted ambiguous API modes")
	}
}

func TestRouteDecisionStoredBeforeNAT(t *testing.T) {
	p, err := New(Config{}, Options{Routes: []Route{
		{Name: "a", Apps: []string{"a.exe"}, Targets: []TargetRule{{Ports: []string{"3724"}}}, Handler: noRouteIO},
		{Name: "b", Apps: []string{"b.exe"}, Targets: []TargetRule{{Ports: []string{"8085"}}}, Handler: noRouteIO},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ app, port, route string }{{"a.exe", "3724", "a"}, {"a.exe", "8085", ""}, {"b.exe", "8085", "b"}, {"b.exe", "3724", ""}} {
		sink := &packetSink{}
		table := newFlowTable(p.cfg.RelayPort, 100)
		router := newPacketRouter(p.cfg, table, func(key tuple) (string, error) { return p.cfg.selectRoute(tc.app, key.remote), nil }, sink.inject)
		packet := testPacket(t, "192.0.2.1:50000", "198.51.100.1:"+tc.port, 1)
		key := packet.key
		router.process(packet.raw, &address{})
		router.resolve(<-router.jobs)
		f := table.forward[key]
		if tc.route == "" {
			if f != nil || sink.modified[0] {
				t.Fatal("cross-route target was intercepted")
			}
		} else {
			if f == nil || f.route != tc.route || !sink.modified[0] {
				t.Fatal("route identity lost before NAT")
			}
		}
		router.stop()
	}
}

func TestUnrestrictedRouteKeepsOtherRoutesRestricted(t *testing.T) {
	p, err := New(Config{}, Options{Routes: []Route{{Name: "a", Apps: []string{"a.exe"}, Targets: []TargetRule{{Ports: []string{"3724"}}}, Handler: noRouteIO}, {Name: "b", Apps: []string{"b.exe"}, Handler: noRouteIO}}})
	if err != nil {
		t.Fatal(err)
	}
	target := netip.MustParseAddrPort("192.0.2.1:443")
	if !p.cfg.targets.matches(target) || p.cfg.selectRoute("a.exe", target) != "" || p.cfg.selectRoute("b.exe", target) != "b" {
		t.Fatal("unrestricted union changed per-app policy")
	}
}

func TestRoutedHandlerDispatch(t *testing.T) {
	target := netip.MustParseAddrPort("192.0.2.1:3724")
	var called string
	routes := []Route{}
	for _, name := range []string{"a", "b"} {
		routes = append(routes, Route{Name: name, Apps: []string{name + ".exe"}, Handler: func(ctx context.Context, c *net.TCPConn, got netip.AddrPort) error {
			if got != target {
				t.Error("original target lost")
			}
			called = name
			return nil
		}})
	}
	p, err := New(Config{}, Options{Routes: routes})
	if err != nil {
		t.Fatal(err)
	}
	routes[1].Handler = nil
	for _, name := range []string{"a", "b"} {
		app, conn := tcpPair(t)
		if err := p.handleRoute(context.Background(), conn, target, name); err != nil {
			t.Fatal(err)
		}
		app.Close()
		if called != name {
			t.Fatalf("handler=%q want=%q", called, name)
		}
	}
	app, conn := tcpPair(t)
	defer app.Close()
	called = ""
	if err := p.handleRoute(context.Background(), conn, target, "missing"); err == nil || called != "" {
		t.Fatal("unknown route invoked handler")
	}
}
