package divert

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func testPacket(t testing.TB, local, remote string, seq uint32) packet {
	t.Helper()
	l := netip.MustParseAddrPort(local)
	r := netip.MustParseAddrPort(remote)
	offset := 20
	src, dst := 12, 16
	if l.Addr().Is6() {
		offset = 40
		src = 8
		dst = 24
	}
	b := make([]byte, offset+20)
	if offset == 20 {
		b[0] = 0x45
		b[9] = 6
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	} else {
		b[0] = 0x60
		b[6] = 6
		binary.BigEndian.PutUint16(b[4:], 20)
	}
	copy(b[src:], l.Addr().AsSlice())
	copy(b[dst:], r.Addr().AsSlice())
	binary.BigEndian.PutUint16(b[offset:], l.Port())
	binary.BigEndian.PutUint16(b[offset+2:], r.Port())
	binary.BigEndian.PutUint32(b[offset+4:], seq)
	b[offset+12] = 0x50
	b[offset+13] = 2
	p, err := parsePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReflectionAndTupleIsolation(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		l, r1, r2 := "192.0.2.1:50000", "198.51.100.1:3724", "198.51.100.2:8085"
		if v6 {
			l = "[2001:db8::1]:50000"
			r1 = "[2001:db8::2]:3724"
			r2 = "[2001:db8::3]:8085"
		}
		table := newFlowTable(34010, 10)
		p := testPacket(t, l, r1, 100)
		q := testPacket(t, l, r2, 200)
		f, err := table.add(p)
		if err != nil {
			t.Fatal(err)
		}
		g, err := table.add(q)
		if err != nil {
			t.Fatal(err)
		}
		if f.translated == g.translated {
			t.Fatal("alias collision")
		}
		if yes, drop := table.rewrite(p); !yes || drop {
			t.Fatal("forward failed")
		}
		reflected, err := parsePacket(p.raw)
		if err != nil {
			t.Fatal(err)
		}
		if reflected.key.local.Addr() != f.original.remote.Addr() || reflected.key.remote.Port() != 34010 || reflected.key.local.Port() != f.translated {
			t.Fatal(reflected.key)
		}
		reply := testPacket(t, reflected.key.remote.String(), reflected.key.local.String(), 400)
		reply.raw[reply.tcp+13] = 18
		reply.ack = true
		if yes, drop := table.rewrite(reply); !yes || drop {
			t.Fatal("reverse failed")
		}
		restored, _ := parsePacket(reply.raw)
		if restored.key.local != f.original.remote || restored.key.remote != f.original.local {
			t.Fatal("lost original target")
		}
		conflicting := testPacket(t, l, r1, 999)
		if yes, drop := table.rewrite(conflicting); !yes || !drop {
			t.Fatal("reused tuple spliced")
		}
		if _, err = table.add(conflicting); err == nil {
			t.Fatal("reused tuple accepted")
		}
		table.release(f)
		table.expire(time.Now().Add(retainClosed + time.Second))
		if _, err = table.add(conflicting); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOwnerUsesEntireTuple(t *testing.T) {
	for _, size := range []int{24, 56} {
		l, r := "192.0.2.1:50000", "198.51.100.2:8085"
		if size == 56 {
			l = "[2001:db8::1]:50000"
			r = "[2001:db8::2]:8085"
		}
		p := testPacket(t, l, r, 1)
		b := make([]byte, 4+size*2)
		binary.LittleEndian.PutUint32(b, 2)
		for i := 0; i < 2; i++ {
			row := b[4+i*size:]
			la, ra, lp, rp, pid := 4, 12, 8, 16, 20
			if size == 56 {
				la, ra, lp, rp, pid = 0, 24, 20, 44, 52
			}
			copy(row[la:], p.key.local.Addr().AsSlice())
			copy(row[ra:], p.key.remote.Addr().AsSlice())
			binary.BigEndian.PutUint16(row[lp:], 50000)
			binary.BigEndian.PutUint16(row[rp:], uint16(8084+i))
			binary.LittleEndian.PutUint32(row[pid:], uint32(100+i))
		}
		pid, err := findOwner(b, size, p.key)
		if err != nil || pid != 101 {
			t.Fatalf("pid=%d err=%v", pid, err)
		}
		if _, err = findOwner(b[:len(b)-1], size, p.key); err == nil {
			t.Fatal("truncation accepted")
		}
	}
}

func TestPacketRejectsFragmentsAndTruncation(t *testing.T) {
	p := testPacket(t, "192.0.2.1:50000", "198.51.100.1:3724", 1)
	p.raw[6] = 0x20
	if _, err := parsePacket(p.raw); err == nil {
		t.Fatal("fragment accepted")
	}
	for n := 0; n < len(p.raw); n++ {
		if _, err := parsePacket(p.raw[:n]); err == nil {
			t.Fatal("truncation accepted")
		}
	}
	p = testPacket(t, "[2001:db8::1]:50000", "[2001:db8::2]:3724", 1)
	p.raw[6] = 44
	if _, err := parsePacket(p.raw); err == nil {
		t.Fatal("IPv6 fragment accepted")
	}
}

func TestProcessMatching(t *testing.T) {
	c := Config{Apps: []string{`C:\Games\Wow.exe`, "Wow-64.exe"}}
	for path, want := range map[string]bool{`c:\games\WOW.EXE`: true, `C:\Other\Wow.exe`: false, `D:\Game\wow-64.EXE`: true, `D:\wow-64.exe.bak`: false} {
		if c.matches(path) != want {
			t.Fatal(path)
		}
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ln.AcceptTCP()
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	return a, b
}

func TestRelayHalfCloseAndTrailingData(t *testing.T) {
	app, local := tcpPair(t)
	upstream, target := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- relayTCP(context.Background(), local, upstream) }()
	request := bytes.Repeat([]byte("request"), 10000)
	if err := writeFull(app, request); err != nil {
		t.Fatal(err)
	}
	app.CloseWrite()
	got, err := io.ReadAll(target)
	if err != nil || !bytes.Equal(got, request) {
		t.Fatalf("request: %d %v", len(got), err)
	}
	if err = writeFull(target, []byte("response after EOF")); err != nil {
		t.Fatal(err)
	}
	target.CloseWrite()
	got, err = io.ReadAll(app)
	if err != nil || string(got) != "response after EOF" {
		t.Fatalf("response: %s %v", got, err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay leaked")
	}
}

func TestRelayCancellation(t *testing.T) {
	app, local := tcpPair(t)
	upstream, target := tcpPair(t)
	_ = app
	_ = target
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relayTCP(ctx, local, upstream) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt reads")
	}
}

func TestSOCKSIPv4AndIPv6AndFailure(t *testing.T) {
	for _, target := range []string{"192.0.2.1:3724", "[2001:db8::1]:8085"} {
		for _, reject := range []bool{false, true} {
			ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			dest := netip.MustParseAddrPort(target)
			go func() {
				c, e := ln.AcceptTCP()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				hello := make([]byte, 3)
				_, e = io.ReadFull(c, hello)
				if e != nil {
					done <- e
					return
				}
				if !bytes.Equal(hello, []byte{5, 1, 0}) {
					done <- io.ErrUnexpectedEOF
					return
				}
				writeFull(c, []byte{5, 0})
				request := make([]byte, 6+len(dest.Addr().AsSlice()))
				_, e = io.ReadFull(c, request)
				if e != nil {
					done <- e
					return
				}
				kind := byte(4)
				if dest.Addr().Is4() {
					kind = 1
				}
				if request[3] != kind || !bytes.Equal(request[4:len(request)-2], dest.Addr().AsSlice()) || binary.BigEndian.Uint16(request[len(request)-2:]) != dest.Port() {
					done <- io.ErrUnexpectedEOF
					return
				}
				status := byte(0)
				if reject {
					status = 5
				}
				e = writeFull(c, []byte{5, status, 0, 1, 0, 0, 0, 0, 0, 0})
				done <- e
			}()
			c, err := dialSOCKS(context.Background(), ln.Addr().String(), dest, time.Second)
			if c != nil {
				c.Close()
			}
			ln.Close()
			if (err != nil) != reject {
				t.Fatalf("reject=%v err=%v", reject, err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		}
	}
}

func FuzzParsePacket(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 60))
	seed := make([]byte, 40)
	seed[0] = 0x45
	seed[9] = 6
	seed[32] = 0x50
	seed[33] = 2
	binary.BigEndian.PutUint16(seed[2:], 40)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := parsePacket(b)
		if err == nil {
			p.reflect(p.key.remote, p.key.local)
		}
	})
}
