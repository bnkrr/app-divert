package divert

import "unsafe"

type address struct {
	Timestamp int64
	Flags     uint32
	Reserved  uint32
	Data      [64]byte
}

// Compile-time ABI checks for the WinDivert 2.2 WINDIVERT_ADDRESS structure.
var _ [80 - unsafe.Sizeof(address{})]byte
var _ [unsafe.Sizeof(address{}) - 80]byte
var _ [16 - unsafe.Offsetof(address{}.Data)]byte
var _ [unsafe.Offsetof(address{}.Data) - 16]byte

const outboundFlag uint32 = 1 << 17
