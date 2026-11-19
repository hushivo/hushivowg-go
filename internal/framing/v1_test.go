// SPDX-License-Identifier: MIT

package framing

import (
	"bytes"
	"errors"
	"testing"
)

func TestV1WireVector(t *testing.T) {
	message := bytes.Repeat([]byte{0x7f}, 258)
	padding := []byte{0x12, 0x34}
	expected := append([]byte{0x01, 0x02}, message...)
	expected = append(expected, padding...)
	format, err := NewV1(len(expected))
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := format.Encode(message, padding)
	if err != nil || !bytes.Equal(datagram, expected) {
		t.Fatalf("Encode did not match the wire vector: %v", err)
	}
	decoded, err := format.Decode(expected)
	if err != nil || !bytes.Equal(decoded, message) {
		t.Fatalf("Decode did not extract the expected message: %v", err)
	}
}

func TestV1RejectsInvalidDatagrams(t *testing.T) {
	format, err := NewV1(4)
	if err != nil {
		t.Fatal(err)
	}
	for _, datagram := range [][]byte{nil, {0}, {0, 0, 1}, {0, 2, 1}, {0, 1, 1, 0, 0}} {
		if _, err := format.Decode(datagram); !errors.Is(err, ErrDatagram) {
			t.Errorf("Decode(%x): got %v, want ErrDatagram", datagram, err)
		}
	}
	if _, err := format.Encode([]byte{1, 2}, []byte{3}); !errors.Is(err, ErrDatagram) {
		t.Fatalf("Encode over budget: got %v, want ErrDatagram", err)
	}
}
