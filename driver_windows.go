//go:build windows && amd64

package divert

import (
	"fmt"
	"golang.org/x/sys/windows"
	"path/filepath"
	"sync"
	"unsafe"
)

type driver struct {
	closeOnce                             sync.Once
	dll                                   *windows.DLL
	handle                                uintptr
	recv, send, checksum, shutdown, close *windows.Proc
}

func openDriver(dir, expression string) (*driver, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, fmt.Errorf("administrator rights required: run app-divert.exe as administrator")
	}
	h, err := windows.LoadLibraryEx(filepath.Join(dir, "WinDivert.dll"), 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("load official x64 WinDivert.dll beside executable: %w", err)
	}
	dll := &windows.DLL{Name: "WinDivert.dll", Handle: h}
	d := &driver{dll: dll}
	names := []string{"WinDivertRecv", "WinDivertSend", "WinDivertHelperCalcChecksums", "WinDivertShutdown", "WinDivertClose"}
	slots := []**windows.Proc{&d.recv, &d.send, &d.checksum, &d.shutdown, &d.close}
	for i, name := range names {
		p, e := dll.FindProc(name)
		if e != nil {
			dll.Release()
			return nil, e
		}
		*slots[i] = p
	}
	open, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		dll.Release()
		return nil, err
	}
	// Loopback and packets injected by other drivers are explicitly outside scope.
	filter, _ := windows.BytePtrFromString(expression)
	handle, _, err := open.Call(uintptr(unsafe.Pointer(filter)), 0, 0, 0)
	if handle == ^uintptr(0) {
		dll.Release()
		return nil, fmt.Errorf("WinDivertOpen (official WinDivert64.sys must be beside DLL): %w", err)
	}
	d.handle = handle
	return d, nil
}
func (d *driver) receive(b []byte, a *address) (int, error) {
	var n uint32
	r, _, err := d.recv.Call(d.handle, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(a)))
	if r == 0 {
		return 0, err
	}
	return int(n), nil
}
func (d *driver) inject(b []byte, a *address, modified bool) error {
	if modified {
		a.Flags &^= outboundFlag
		r, _, err := d.checksum.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(a)), 0)
		if r == 0 {
			return fmt.Errorf("calculate checksums: %w", err)
		}
	}
	var n uint32
	r, _, err := d.send.Call(d.handle, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(a)))
	if r == 0 {
		return err
	}
	if int(n) != len(b) {
		return fmt.Errorf("partial packet injection")
	}
	return nil
}
func (d *driver) stopReceive() error {
	r, _, err := d.shutdown.Call(d.handle, 1)
	if r == 0 {
		return err
	}
	return nil
}
func (d *driver) closeHandle() { d.closeOnce.Do(func() { d.close.Call(d.handle) }) }
func (d *driver) dispose()     { d.closeHandle(); d.dll.Release() }
