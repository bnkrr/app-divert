//go:build windows && amd64

package divert

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

func (p *Proxy) run(ctx context.Context) error {
	cfg, dllDir := p.cfg, p.opts.DLLDir
	logger := p.opts.Logger
	var listeners []*net.TCPListener
	for _, binding := range []struct{ network, address string }{{"tcp4", fmt.Sprintf("0.0.0.0:%d", cfg.RelayPort)}, {"tcp6", fmt.Sprintf("[::]:%d", cfg.RelayPort)}} {
		addr, err := net.ResolveTCPAddr(binding.network, binding.address)
		if err != nil {
			return err
		}
		ln, err := net.ListenTCP(binding.network, addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return fmt.Errorf("listen %s: %w", binding.address, err)
		}
		listeners = append(listeners, ln)
	}
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()
	d, err := openDriver(dllDir, cfg.packetFilter())
	if err != nil {
		return err
	}
	defer d.dispose()
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	table := newFlowTable(cfg.RelayPort, cfg.MaxConnections)
	failures := make(chan error, 1)
	fail := func(err error) {
		select {
		case failures <- err:
		default:
		}
	}
	inject := func(b []byte, a *address, modified bool) {
		if err := d.inject(b, a, modified); err != nil {
			fail(fmt.Errorf("inject packet: %w", err))
		}
	}
	var accepts, handlers, workers sync.WaitGroup
	for _, ln := range listeners {
		accepts.Add(1)
		go func(ln *net.TCPListener) {
			defer accepts.Done()
			for {
				c, err := ln.AcceptTCP()
				if err != nil {
					if relayCtx.Err() == nil {
						fail(err)
					}
					return
				}
				f := table.claim(c)
				if f == nil {
					resetTCP(c)
					continue
				}
				handlers.Add(1)
				go func() {
					defer handlers.Done()
					defer table.release(f)
					logger.Printf("proxy %s -> %s", f.original.local, f.original.remote)
					if err := p.handle(relayCtx, c, f.original.remote); err != nil && relayCtx.Err() == nil {
						logger.Printf("closed %s: %v", f.original.remote, err)
					}
				}()
			}
		}(ln)
	}
	matcher := newProcessMatcher(cfg)
	defer matcher.close()
	router := newPacketRouter(cfg, table, matcher.matches, inject)
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range router.jobs {
				router.resolve(job)
			}
		}()
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		b := make([]byte, 65575)
		var a address
		for {
			n, err := d.receive(b, &a)
			if err != nil {
				if relayCtx.Err() == nil {
					fail(fmt.Errorf("receive packet: %w", err))
				}
				return
			}
			router.process(b[:n], &a)
		}
	}()
	janitorDone := make(chan struct{})
	go func() {
		defer close(janitorDone)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		nextMaintenance := time.Now()
		for {
			select {
			case <-relayCtx.Done():
				router.stop()
				return
			case now := <-ticker.C:
				router.expire(now)
				if now.Before(nextMaintenance) {
					continue
				}
				nextMaintenance = now.Add(time.Second)
				if counts := router.takeFallbacks(); counts != ([5]uint64{}) {
					logger.Printf("new connections bypassed: owner=%d queue=%d timeout=%d mapping=%d cache_exhausted=%d", counts[0], counts[1], counts[2], counts[3], counts[4])
				}
				table.mu.Lock()
				table.expire(now)
				table.mu.Unlock()
			}
		}
	}()
	close(p.ready)
	logger.Printf("ready: apps=%v targets=%v SOCKS5=%s TCP relay=%d (IPv4 + IPv6)", cfg.Apps, cfg.Targets, cfg.SOCKS5, cfg.RelayPort)
	select {
	case <-ctx.Done():
	case err = <-failures:
	}
	cancel()
	router.stop()
	table.stop()
	for _, ln := range listeners {
		ln.Close()
	}
	accepts.Wait()
	handlers.Wait()
	// Keep interception and NAT maps alive while socket resets leave the stack.
	timer := time.NewTimer(200 * time.Millisecond)
	<-timer.C
	if e := d.stopReceive(); e != nil {
		err = errors.Join(err, e)
		d.closeHandle()
	}
	<-readDone
	workers.Wait()
	<-janitorDone
	return err
}
