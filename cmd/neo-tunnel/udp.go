package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// frp's installed UDP profiles use a 1500-byte payload budget.
const udpPayload = 1500

type udpSettings struct {
	Listen string `json:"listen"`
}

func udpConfig(site siteSettings) udpSettings {
	return udpSettings{Listen: net.JoinHostPort(site.Bind, strconv.Itoa(site.Port))}
}

func serveUDP(ctx context.Context, config udpSettings) error {
	addr, err := netip.ParseAddrPort(config.Listen)
	if err != nil || (addr.Addr().String() != "0.0.0.0" && addr.Addr().String() != "127.0.0.1") || addr.Port() < 1024 {
		return errors.New("invalid UDP listener; expected IPv4 wildcard or loopback and an unprivileged port")
	}
	edge, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return err
	}
	defer edge.Close()
	return relayUDP(ctx, edge, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 17101}, 2048, 60*time.Second)
}

func relayUDP(ctx context.Context, edge *net.UDPConn, upstream *net.UDPAddr, capacity int, idle time.Duration) error {
	sessions := make(map[netip.AddrPort]*net.UDPConn)
	var mu sync.Mutex
	var replies sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = edge.Close() })
	defer func() {
		stop()
		mu.Lock()
		for _, session := range sessions {
			_ = session.Close()
		}
		mu.Unlock()
		replies.Wait()
	}()

	var data [udpPayload + 1]byte
	for {
		n, peer, err := edge.ReadFromUDPAddrPort(data[:])
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n > udpPayload {
			continue
		}
		mu.Lock()
		conn := sessions[peer]
		if conn == nil && len(sessions) < capacity {
			conn, err = net.DialUDP("udp4", nil, upstream)
			if err == nil {
				sessions[peer] = conn
				_ = conn.SetReadDeadline(time.Now().Add(idle))
				replies.Go(func() {
					defer func() {
						mu.Lock()
						delete(sessions, peer)
						_ = conn.Close()
						mu.Unlock()
					}()
					var reply [udpPayload + 1]byte
					for {
						n, err := conn.Read(reply[:])
						if err != nil {
							return
						}
						if n <= udpPayload {
							_, _ = edge.WriteToUDPAddrPort(reply[:n], peer)
						}
					}
				})
			}
		}
		if conn != nil {
			_ = conn.SetReadDeadline(time.Now().Add(idle))
			_, _ = conn.Write(data[:n])
		}
		mu.Unlock()
	}
}
