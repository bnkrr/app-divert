//go:build windows && amd64

package divert

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

// Uses the official DLL helpers, without loading the kernel driver or requiring
// elevation. Set APP_DIVERT_TEST_DLL_DIR to a trusted WinDivert 2.2.2 directory.
func TestWindowsKernelFilterExpressions(t *testing.T) {
	dir := os.Getenv("APP_DIVERT_TEST_DLL_DIR")
	if dir == "" {
		t.Skip("set APP_DIVERT_TEST_DLL_DIR for official WinDivert filter validation")
	}
	h, err := windows.LoadLibraryEx(filepath.Join(dir, "WinDivert.dll"), 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		t.Fatal(err)
	}
	dll := &windows.DLL{Name: "WinDivert.dll", Handle: h}
	defer dll.Release()
	compile := dll.MustFindProc("WinDivertHelperCompileFilter")
	evaluate := dll.MustFindProc("WinDivertHelperEvalFilter")
	rules := [][]TargetRule{nil, {{Ports: []string{"3724", "8000-8100"}}}, {{IPs: []string{"192.0.2.0/24", "2001:db8:1::/48"}, Ports: []string{"3724"}}, {IPs: []string{"198.51.100.1", "2001:db8:2::1"}, Ports: []string{"8085"}}}, {{IPs: []string{"0.0.0.0/0", "::/0"}}}}
	// Exercise the configured maximum rather than discovering a driver filter
	// instruction limit only when an end user starts interception.
	var many []string
	for i := 0; i < 64; i++ {
		many = append(many, fmt.Sprintf("2001:db8:%x::/48", i))
	}
	rules = append(rules, []TargetRule{{IPs: many}})
	for _, rules := range rules {
		cfg, err := (Config{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:1080", Targets: rules}).normalized(false)
		if err != nil {
			t.Fatal(err)
		}
		expression, _ := windows.BytePtrFromString(cfg.packetFilter())
		var pos uint32
		ok, _, err := compile.Call(uintptr(unsafe.Pointer(expression)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&pos)))
		if ok == 0 {
			t.Fatalf("filter compilation failed at %d: %v\n%s", pos, err, cfg.packetFilter())
		}
		for _, target := range []string{"192.0.2.0:3724", "192.0.2.255:3724", "192.0.3.1:3724", "192.0.2.1:8000", "198.51.100.1:8085", "[2001:db8:1::1]:3724", "[2001:db8:2::1]:8085", "[2001:db8:3::1]:3724", "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"} {
			local := "198.18.0.1:50000"
			if target[0] == '[' {
				local = "[2001:db8:ffff::1]:50000"
			}
			p := testPacket(t, local, target, 1)
			addr := address{Flags: outboundFlag}
			if p.width == 16 {
				addr.Flags |= 1 << 20
			}
			ok, _, _ := evaluate.Call(uintptr(unsafe.Pointer(expression)), uintptr(unsafe.Pointer(&p.raw[0])), uintptr(len(p.raw)), uintptr(unsafe.Pointer(&addr)))
			if (ok != 0) != cfg.targets.matches(p.key.remote) {
				t.Fatalf("kernel/user scope mismatch: %s got=%v want=%v filter=%s", target, ok != 0, cfg.targets.matches(p.key.remote), cfg.packetFilter())
			}
			addr.Flags = 0
			ok, _, _ = evaluate.Call(uintptr(unsafe.Pointer(expression)), uintptr(unsafe.Pointer(&p.raw[0])), uintptr(len(p.raw)), uintptr(unsafe.Pointer(&addr)))
			if ok != 0 {
				t.Fatal("ordinary inbound packet captured")
			}
		}
		for _, ends := range [][2]string{{"192.0.2.1:34010", "198.51.100.1:49152"}, {"[2001:db8::1]:34010", "[2001:db8::2]:49152"}} {
			p := testPacket(t, ends[0], ends[1], 1)
			addr := address{Flags: outboundFlag}
			if p.width == 16 {
				addr.Flags |= 1 << 20
			}
			ok, _, _ := evaluate.Call(uintptr(unsafe.Pointer(expression)), uintptr(unsafe.Pointer(&p.raw[0])), uintptr(len(p.raw)), uintptr(unsafe.Pointer(&addr)))
			if ok == 0 {
				t.Fatal("relay return path excluded")
			}
		}
	}
}
