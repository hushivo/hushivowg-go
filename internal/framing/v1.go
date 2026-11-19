// SPDX-License-Identifier: MIT

// Package framing implements the HushivoWG UDP datagram format.
package framing

import (
	"encoding/binary"
	"errors"
)

const (
	// V1HeaderSize is the number of bytes prepended to each WireGuard message.
	V1HeaderSize = 2
	// MaxPayload is the maximum standard IPv4 UDP payload, without IP options.
	MaxPayload = 65507
)

var (
	ErrBudget   = errors.New("invalid HushivoWG UDP payload budget")
	ErrDatagram = errors.New("invalid HushivoWG datagram")
)

// V1 encodes and decodes datagrams within a configured UDP payload budget.
type V1 struct {
	budget int
}

func NewV1(budget int) (V1, error) {
	if budget <= V1HeaderSize || budget > MaxPayload {
		return V1{}, ErrBudget
	}
	return V1{budget: budget}, nil
}

// Encode writes one WireGuard message and optional padding into a new datagram.
func (f V1) Encode(message, padding []byte) ([]byte, error) {
	available := f.budget - V1HeaderSize
	if len(message) == 0 || len(message) > available || len(padding) > available-len(message) {
		return nil, ErrDatagram
	}
	datagram := make([]byte, V1HeaderSize+len(message)+len(padding))
	binary.BigEndian.PutUint16(datagram, uint16(len(message)))
	copy(datagram[V1HeaderSize:], message)
	copy(datagram[V1HeaderSize+len(message):], padding)
	return datagram, nil
}

// Decode returns a view of the embedded message. WireGuard must still
// authenticate the message before acting on its contents.
func (f V1) Decode(datagram []byte) ([]byte, error) {
	if len(datagram) <= V1HeaderSize || len(datagram) > f.budget {
		return nil, ErrDatagram
	}
	size := int(binary.BigEndian.Uint16(datagram))
	if size == 0 || size > len(datagram)-V1HeaderSize {
		return nil, ErrDatagram
	}
	end := V1HeaderSize + size
	return datagram[V1HeaderSize:end:end], nil
}
