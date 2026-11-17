// Package canary implements the challenge-response used by NEO UDP health checks.
package canary

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"time"
)

const UDPAsk = "BHP1"
const UDPAck = "BHA1"
const UDPSize = len(UDPAsk) + 16

func CheckUDP(addr string, timeout time.Duration) error {
	var packet [UDPSize]byte
	copy(packet[:], UDPAsk)
	if _, err := rand.Read(packet[len(UDPAsk):]); err != nil {
		return err
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := conn.Write(packet[:]); err != nil {
		return err
	}
	var reply [UDPSize + 1]byte
	n, err := conn.Read(reply[:])
	if err != nil {
		return err
	}
	copy(packet[:], UDPAck)
	if !bytes.Equal(reply[:n], packet[:]) {
		return errors.New("unexpected UDP canary response")
	}
	return nil
}
