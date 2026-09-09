package divert

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

type tuple struct{ local, remote netip.AddrPort }
type packet struct {
	raw                  []byte
	key                  tuple
	tcp, src, dst, width int
	syn, ack, rst        bool
	seq                  uint32
}

// Only complete TCP packets are rewritten. IPv6 extension headers are walked
// with bounds checks; routing headers, fragments, AH and ESP are never modified.
func parsePacket(b []byte) (p packet, err error) {
	fail := func() (packet, error) { return packet{}, errors.New("unsupported or malformed TCP packet") }
	if len(b) < 20 {
		return fail()
	}
	p.raw = b
	switch b[0] >> 4 {
	case 4:
		n := int(binary.BigEndian.Uint16(b[2:4]))
		h := int(b[0]&15) * 4
		if n != len(b) || h < 20 || h > n || b[9] != 6 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return fail()
		}
		p.tcp = h
		p.src = 12
		p.dst = 16
		p.width = 4
	case 6:
		if len(b) < 40 || int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) {
			return fail()
		}
		p.src = 8
		p.dst = 24
		p.width = 16
		p.tcp = 40
		next := b[6]
		for next != 6 {
			if next != 0 && next != 60 {
				return fail()
			}
			if p.tcp+2 > len(b) {
				return fail()
			}
			n := (int(b[p.tcp+1]) + 1) * 8
			next = b[p.tcp]
			p.tcp += n
			if p.tcp > len(b) {
				return fail()
			}
		}
	default:
		return fail()
	}
	if p.tcp+20 > len(b) {
		return fail()
	}
	h := int(b[p.tcp+12]>>4) * 4
	if h < 20 || p.tcp+h > len(b) {
		return fail()
	}
	l, _ := netip.AddrFromSlice(b[p.src : p.src+p.width])
	r, _ := netip.AddrFromSlice(b[p.dst : p.dst+p.width])
	p.key = tuple{netip.AddrPortFrom(l, binary.BigEndian.Uint16(b[p.tcp:])), netip.AddrPortFrom(r, binary.BigEndian.Uint16(b[p.tcp+2:]))}
	flags := b[p.tcp+13]
	p.syn = flags&2 != 0
	p.ack = flags&16 != 0
	p.rst = flags&4 != 0
	p.seq = binary.BigEndian.Uint32(b[p.tcp+4:])
	return p, nil
}

// reflect changes only endpoints. WinDivertHelperCalcChecksums runs afterwards,
// including when Windows provided checksum-offloaded packets.
func (p packet) reflect(src, dst netip.AddrPort) {
	copy(p.raw[p.src:p.src+p.width], src.Addr().AsSlice())
	copy(p.raw[p.dst:p.dst+p.width], dst.Addr().AsSlice())
	binary.BigEndian.PutUint16(p.raw[p.tcp:], src.Port())
	binary.BigEndian.PutUint16(p.raw[p.tcp+2:], dst.Port())
}
