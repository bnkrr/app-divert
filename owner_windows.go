//go:build windows && amd64

package divert

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"sync"
	"time"
	"unsafe"
)

var getTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

func connectionOwner(key tuple) (uint32, error) {
	family := uintptr(windows.AF_INET)
	rowSize := 24
	if key.local.Addr().Is6() {
		family = windows.AF_INET6
		rowSize = 56
	}
	var size uint32
	r, _, _ := getTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, 5, 0) // TCP_TABLE_OWNER_PID_ALL
	if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && r != 0 {
		return 0, windows.Errno(r)
	}
	for attempt := 0; attempt < 4; attempt++ {
		if size < 4 || size > 64*1024*1024 {
			return 0, fmt.Errorf("invalid TCP owner table size %d", size)
		}
		b := make([]byte, size)
		r, _, _ = getTCPTable.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, family, 5, 0)
		if r == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if r != 0 {
			return 0, windows.Errno(r)
		}
		return findOwner(b, rowSize, key)
	}
	return 0, fmt.Errorf("TCP owner table changed repeatedly")
}

// Cached handles identify a process instance, not just its reusable PID.
// SYN ownership still uses the full TCP tuple for every new connection.
type processDecision struct {
	handle  windows.Handle
	path    string
	expires time.Time
}
type processMatcher struct {
	mu    sync.Mutex
	cfg   Config
	self  uint32
	cache map[uint32]processDecision
}

func newProcessMatcher(cfg Config) *processMatcher {
	return &processMatcher{cfg: cfg, self: uint32(os.Getpid()), cache: make(map[uint32]processDecision)}
}
func (m *processMatcher) matches(key tuple) (string, error) {
	pid, err := connectionOwner(key)
	if err != nil {
		return "", err
	}
	if pid == m.self {
		return "", nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if cached, ok := m.cache[pid]; ok {
		status, err := windows.WaitForSingleObject(cached.handle, 0)
		if err == nil && status == uint32(windows.WAIT_TIMEOUT) && now.Before(cached.expires) {
			return m.cfg.selectRoute(cached.path, key.remote), nil
		}
		windows.CloseHandle(cached.handle)
		delete(m.cache, pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return "", err
	}
	name := make([]uint16, 32768)
	size := uint32(len(name))
	if err = windows.QueryFullProcessImageName(h, 0, &name[0], &size); err != nil {
		windows.CloseHandle(h)
		return "", err
	}
	path := windows.UTF16ToString(name[:size])
	if len(m.cache) >= 256 {
		for pid, cached := range m.cache {
			if !now.Before(cached.expires) {
				windows.CloseHandle(cached.handle)
				delete(m.cache, pid)
			}
		}
	}
	if len(m.cache) < 256 {
		m.cache[pid] = processDecision{h, path, now.Add(time.Minute)}
	} else {
		windows.CloseHandle(h)
	}
	return m.cfg.selectRoute(path, key.remote), nil
}
func (m *processMatcher) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for pid, cached := range m.cache {
		windows.CloseHandle(cached.handle)
		delete(m.cache, pid)
	}
}
