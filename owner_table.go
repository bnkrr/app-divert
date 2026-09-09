package divert

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

func findOwner(b []byte, rowSize int, key tuple) (uint32, error) {
	if len(b) < 4 || (rowSize != 24 && rowSize != 56) {
		return 0, fmt.Errorf("invalid TCP owner table")
	}
	count := uint64(binary.LittleEndian.Uint32(b))
	if count > uint64((len(b)-4)/rowSize) {
		return 0, fmt.Errorf("truncated TCP owner table")
	}
	for i := 0; i < int(count); i++ {
		row := b[4+i*rowSize : 4+(i+1)*rowSize]
		la, ra, lp, rp, pid, width := 4, 12, 8, 16, 20, 4
		if rowSize == 56 {
			la = 0
			ra = 24
			lp = 20
			rp = 44
			pid = 52
			width = 16
		}
		l, _ := netip.AddrFromSlice(row[la : la+width])
		r, _ := netip.AddrFromSlice(row[ra : ra+width])
		if l == key.local.Addr() && r == key.remote.Addr() && binary.BigEndian.Uint16(row[lp:]) == key.local.Port() && binary.BigEndian.Uint16(row[rp:]) == key.remote.Port() {
			owner := binary.LittleEndian.Uint32(row[pid:])
			if owner != 0 {
				return owner, nil
			}
		}
	}
	return 0, fmt.Errorf("TCP owner not available for %s -> %s", key.local, key.remote)
}
