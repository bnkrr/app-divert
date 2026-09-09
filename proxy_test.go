package divert

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestNewValidationAndSnapshot(t *testing.T) {
	cfg := Config{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:1080"}
	p, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Apps[0] = "other.exe"
	if !p.cfg.matches(`C:\games\game.exe`) || p.cfg.matches("other.exe") {
		t.Fatal("proxy retained caller's mutable Apps slice")
	}
	if p.cfg.RelayPort != 34010 || p.cfg.ConnectTimeoutSeconds != 10 || p.cfg.MaxConnections != 4096 {
		t.Fatalf("missing defaults: %+v", p.cfg)
	}
	for _, cfg := range []Config{
		{},
		{Apps: []string{"*.exe"}, SOCKS5: "127.0.0.1:1080"},
		{Apps: []string{"game.exe"}, SOCKS5: "localhost:1080"},
		{Apps: []string{"game.exe"}, SOCKS5: "192.0.2.1:1080"},
		{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:34010"},
		{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:1080", MaxConnections: -1},
		{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:1080", ConnectTimeoutSeconds: 121},
	} {
		if _, err := New(cfg, Options{}); err == nil {
			t.Fatalf("accepted %+v", cfg)
		}
	}
	handler := func(context.Context, *net.TCPConn, netip.AddrPort) error { return nil }
	if _, err := New(Config{Apps: []string{"game.exe"}}, Options{Handler: handler}); err != nil {
		t.Fatalf("custom handler required SOCKS: %v", err)
	}
	if _, err := New(cfg, Options{Handler: handler}); err == nil {
		t.Fatal("ambiguous forwarding accepted")
	}
}

func TestRunLifecycleWithoutDriver(t *testing.T) {
	p, err := New(Config{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:1080"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Ready():
		t.Fatal("canceled startup reported ready")
	default:
	}
	if err := p.Run(ctx); !errors.Is(err, ErrAlreadyRun) {
		t.Fatalf("second run: %v", err)
	}
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		p, _ := New(Config{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:1080"}, Options{})
		if err := p.Run(context.Background()); !errors.Is(err, ErrUnsupportedPlatform) {
			t.Fatal(err)
		}
		select {
		case <-p.Ready():
			t.Fatal("failed startup reported ready")
		default:
		}
	}
}

func TestHandlerTargetHalfCloseAndCleanup(t *testing.T) {
	app, conn := tcpPair(t)
	defer app.Close()
	_ = app.SetDeadline(time.Now().Add(3 * time.Second))
	target := netip.MustParseAddrPort("[2001:db8::123]:3724")
	p, err := New(Config{Apps: []string{"game.exe"}}, Options{
		Handler: func(ctx context.Context, c *net.TCPConn, got netip.AddrPort) error {
			if got != target {
				return errors.New("original target lost")
			}
			payload, err := io.ReadAll(c)
			if err != nil {
				return err
			}
			_, err = c.Write(append([]byte("reply:"), payload...))
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.handle(context.Background(), conn, target) }()
	if _, err := app.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(app)
	if err != nil || string(got) != "reply:request" {
		t.Fatalf("response %q: %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("after return")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("not closed: %v", err)
	}
}

func TestHandlerFailureResetsConnection(t *testing.T) {
	app, conn := tcpPair(t)
	defer app.Close()
	_ = app.SetDeadline(time.Now().Add(3 * time.Second))
	want := errors.New("upstream failed")
	p, err := New(Config{Apps: []string{"game.exe"}}, Options{
		Handler: func(context.Context, *net.TCPConn, netip.AddrPort) error { return want },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.handle(context.Background(), conn, netip.MustParseAddrPort("192.0.2.1:80")); !errors.Is(err, want) {
		t.Fatal(err)
	}
	_, err = app.Read(make([]byte, 1))
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("expected reset, got %v", err)
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("reset timed out")
	}
}

func TestLoadConfigStrict(t *testing.T) {
	// t.TempDir uses the system temporary directory and cleans up after the test.
	path := filepath.Join(t.TempDir(), "config.json")
	for _, input := range []string{
		`{"apps":["game.exe"],"socks5":"127.0.0.1:1080","unknown":true}`,
		`{"apps":["game.exe"],"socks5":"127.0.0.1:1080"} {}`,
		`{"apps":["game.exe"]}`,
		`null`,
	} {
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	if err := os.WriteFile(path, []byte(`{"apps":["game.exe"],"socks5":"[::1]:1080"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
}
