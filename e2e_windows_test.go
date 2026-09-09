//go:build windows && amd64

package divert

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in real-driver test. Targets must be controlled echo endpoints, in pairs:
// eligible port, excluded port, repeated for each address family. Each endpoint
// sends "app-divert-e2e\n", reads until EOF (max 1 MiB), then echoes the bytes.
// Requires elevation and APP_DIVERT_TEST_DLL_DIR. No public/game endpoint is used
// by default. Child copies exercise both matching and nonmatching executables.
func TestWindowsDiversionE2E(t *testing.T) {
	value := os.Getenv("APP_DIVERT_E2E_TARGETS")
	if value == "" {
		t.Skip("set APP_DIVERT_E2E_TARGETS to controlled endpoint pairs")
	}
	var targets []netip.AddrPort
	for _, part := range strings.Split(value, ",") {
		target, err := netip.ParseAddrPort(part)
		if err != nil {
			t.Fatal(err)
		}
		if !target.Addr().IsGlobalUnicast() || target.Addr().IsLoopback() {
			t.Fatal("endpoint must be remote unicast")
		}
		targets = append(targets, target)
	}
	if len(targets) == 0 || len(targets)%2 != 0 {
		t.Fatal("expected eligible/excluded endpoint pairs")
	}
	dir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	selected := filepath.Join(dir, "selected-client.exe")
	other := filepath.Join(dir, "other-client.exe")
	for _, name := range []string{selected, other} {
		if err = os.WriteFile(name, binary, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var hits atomic.Int32
	var rules []TargetRule
	for i := 0; i < len(targets); i += 2 {
		rules = append(rules, TargetRule{IPs: []string{targets[i].Addr().String()}, Ports: []string{strconv.Itoa(int(targets[i].Port()))}})
	}
	cfg := Config{Apps: []string{selected}, Targets: rules, RelayPort: 34019}
	ctx, cancel := context.WithCancel(context.Background())
	proxy, err := New(cfg, Options{DLLDir: os.Getenv("APP_DIVERT_TEST_DLL_DIR"), Handler: func(ctx context.Context, c *net.TCPConn, target netip.AddrPort) error {
		hits.Add(1)
		upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target.String())
		if err != nil {
			return err
		}
		return relayTCP(ctx, c, upstream.(*net.TCPConn))
	}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- proxy.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("proxy shutdown timed out")
		}
	})
	select {
	case <-proxy.Ready():
	case err := <-done:
		done <- err
		t.Fatalf("startup: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("startup timed out")
	}
	for i, target := range targets {
		for _, client := range []string{selected, other} {
			for _, size := range []int{1, 65536} {
				before := hits.Load()
				command := exec.Command(client, "-test.run=^TestWindowsE2EClient$", "-test.timeout=15s")
				command.Env = append(os.Environ(), "APP_DIVERT_E2E_CLIENT="+target.String(), "APP_DIVERT_E2E_BYTES="+strconv.Itoa(size))
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("%s %s: %v\n%s", filepath.Base(client), target, err, output)
				}
				want := int32(0)
				if client == selected && i%2 == 0 {
					want = 1
				}
				if got := hits.Load() - before; got != want {
					t.Fatalf("%s %s: handler calls=%d want=%d", filepath.Base(client), target, got, want)
				}
				t.Logf("PASS client=%s family=%d eligible=%t bytes=%d proxied=%t", filepath.Base(client), target.Addr().BitLen(), i%2 == 0, size, want == 1)
			}
		}
	}
	// Connection bursts exercise parallel owner workers and process-handle reuse.
	var commands []*exec.Cmd
	before := hits.Load()
	for i := 0; i < 8; i++ {
		cmd := exec.Command(selected, "-test.run=^TestWindowsE2EClient$", "-test.timeout=15s")
		cmd.Env = append(os.Environ(), "APP_DIVERT_E2E_CLIENT="+targets[(i%(len(targets)/2))*2].String(), "APP_DIVERT_E2E_BYTES=65536")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, cmd)
	}
	for _, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	if got := hits.Load() - before; got != 8 {
		t.Fatalf("parallel handler calls=%d want=8", got)
	}
	t.Log("PASS eight parallel proxied connections")
}

func TestWindowsE2EClient(t *testing.T) {
	target := os.Getenv("APP_DIVERT_E2E_CLIENT")
	if target == "" {
		t.Skip("internal controlled client helper")
	}
	size, err := strconv.Atoi(os.Getenv("APP_DIVERT_E2E_BYTES"))
	if err != nil || size < 1 || size > 1<<20 {
		t.Fatal("invalid payload size")
	}
	c, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	greeting := make([]byte, len("app-divert-e2e\n"))
	if _, err = io.ReadFull(c, greeting); err != nil || string(greeting) != "app-divert-e2e\n" {
		t.Fatalf("server-first greeting: %q %v", greeting, err)
	}
	payload := bytes.Repeat([]byte{0x35}, size)
	if err = writeFull(c, payload); err != nil {
		t.Fatal(err)
	}
	if err = c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(reply, payload) {
		t.Fatal(fmt.Sprintf("half-close echo: length=%d error=%v", len(reply), err))
	}
}

// Fault injection exercises the real driver's unmodified reinjection path.
// The lookup stub is local to this test; production configuration has no hook
// that can replace process ownership checks.
func TestWindowsFailOpenE2E(t *testing.T) {
	value := os.Getenv("APP_DIVERT_E2E_TARGETS")
	if value == "" {
		t.Skip("set APP_DIVERT_E2E_TARGETS to controlled endpoint pairs")
	}
	parts := strings.Split(value, ",")
	if len(parts)%2 != 0 {
		t.Fatal("expected endpoint pairs")
	}
	var targets []netip.AddrPort
	var rules []TargetRule
	for i := 0; i < len(parts); i += 2 {
		target, err := netip.ParseAddrPort(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
		rules = append(rules, TargetRule{IPs: []string{target.Addr().String()}, Ports: []string{strconv.Itoa(int(target.Port()))}})
	}
	for _, mode := range []string{"owner-error", "queue-full", "lookup-timeout", "mapping-full", "cache-full"} {
		t.Run(mode, func(t *testing.T) {
			cfg, err := (Config{Apps: []string{"unused.exe"}, SOCKS5: "127.0.0.1:1080", Targets: rules, RelayPort: 34019}).normalized(false)
			if err != nil {
				t.Fatal(err)
			}
			d, err := openDriver(os.Getenv("APP_DIVERT_TEST_DLL_DIR"), cfg.packetFilter())
			if err != nil {
				t.Fatal(err)
			}
			var modified atomic.Int32
			failures := make(chan error, 1)
			inject := func(b []byte, a *address, changed bool) {
				if changed {
					modified.Add(1)
				}
				if err := d.inject(b, a, changed); err != nil {
					select {
					case failures <- err:
					default:
					}
				}
			}
			owner := func(tuple) (string, error) {
				if mode == "lookup-timeout" {
					time.Sleep(150 * time.Millisecond)
					return "default", nil
				}
				if mode == "mapping-full" {
					return "default", nil
				}
				return "", fmt.Errorf("controlled owner lookup failure")
			}
			router := newPacketRouter(cfg, newFlowTable(cfg.RelayPort, 0), owner, inject)
			if mode == "queue-full" {
				router.jobs = make(chan *ownerJob)
			}
			if mode == "cache-full" {
				router.limit = 0
			}
			var wg sync.WaitGroup
			if mode != "queue-full" {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for job := range router.jobs {
						router.resolve(job)
					}
				}()
			}
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				b := make([]byte, 65575)
				for {
					var a address
					n, err := d.receive(b, &a)
					if err != nil {
						return
					}
					router.process(b[:n], &a)
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			wg.Add(1)
			go func() {
				defer wg.Done()
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case now := <-ticker.C:
						router.expire(now)
					}
				}
			}()
			defer func() {
				cancel()
				router.stop()
				if err := d.stopReceive(); err != nil {
					d.closeHandle()
				}
				<-readDone
				wg.Wait()
				d.dispose()
			}()
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range targets {
				cmd := exec.Command(self, "-test.run=^TestWindowsE2EClient$", "-test.timeout=15s")
				cmd.Env = append(os.Environ(), "APP_DIVERT_E2E_CLIENT="+target.String(), "APP_DIVERT_E2E_BYTES=65536")
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s: %v\n%s", target, err, output)
				}
				t.Logf("PASS direct fallback=%s family=%d bytes=65536", mode, target.Addr().BitLen())
			}
			if modified.Load() != 0 {
				t.Fatal("fallback modified a packet")
			}
			select {
			case err := <-failures:
				t.Fatal(err)
			default:
			}
			counts := router.takeFallbacks()
			index := map[string]int{"owner-error": 0, "queue-full": 1, "lookup-timeout": 2, "mapping-full": 3, "cache-full": 4}[mode]
			if counts[index] == 0 {
				t.Fatal("fault path was not exercised")
			}
		})
	}
}
