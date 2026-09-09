package divert

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

func dialSOCKS(ctx context.Context, proxy string, target netip.AddrPort, timeout time.Duration) (conn *net.TCPConn, err error) {
	dialer := net.Dialer{Timeout: timeout}
	c, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	conn = c.(*net.TCPConn)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err = writeFull(conn, []byte{5, 1, 0}); err != nil {
		return conn, err
	}
	var reply [2]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		return conn, err
	}
	if reply != [2]byte{5, 0} {
		return conn, fmt.Errorf("SOCKS5 server must accept NOAUTH, got %v", reply)
	}
	kind := byte(4)
	if target.Addr().Is4() {
		kind = 1
	}
	request := append([]byte{5, 1, 0, kind}, target.Addr().AsSlice()...)
	request = binary.BigEndian.AppendUint16(request, target.Port())
	if err = writeFull(conn, request); err != nil {
		return conn, err
	}
	var h [4]byte
	if _, err = io.ReadFull(conn, h[:]); err != nil {
		return conn, err
	}
	if h[0] != 5 || h[1] != 0 || h[2] != 0 {
		return conn, fmt.Errorf("SOCKS5 CONNECT failed: %v", h)
	}
	n := 0
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var size [1]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return conn, err
		}
		n = int(size[0])
	default:
		return conn, fmt.Errorf("invalid SOCKS5 address type %d", h[3])
	}
	if _, err = io.CopyN(io.Discard, conn, int64(n+2)); err != nil {
		return conn, err
	}
	err = conn.SetDeadline(time.Time{})
	return conn, err
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// EOF closes only the matching write direction; resets/cancellation close both.
func relayTCP(ctx context.Context, a, b *net.TCPConn) error {
	stop := context.AfterFunc(ctx, func() { resetTCP(a); resetTCP(b) })
	defer stop()
	defer a.Close()
	defer b.Close()
	result := make(chan error, 2)
	copyOne := func(dst, src *net.TCPConn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			err = dst.CloseWrite()
		}
		result <- err
	}
	go copyOne(a, b)
	go copyOne(b, a)
	first := <-result
	if first != nil {
		resetTCP(a)
		resetTCP(b)
	}
	second := <-result
	if second != nil {
		resetTCP(a)
		resetTCP(b)
	}
	if first != nil {
		return first
	}
	return second
}
func resetTCP(c *net.TCPConn) { _ = c.SetLinger(0); _ = c.Close() }
