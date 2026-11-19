// SPDX-License-Identifier: MIT

package conn

import (
	"bytes"
	"testing"
)

type framingTestBind struct {
	Bind
	sent [][]byte
}

func (b *framingTestBind) Send(packets [][]byte, _ Endpoint) error {
	b.sent = packets
	return nil
}

func (b *framingTestBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	return []ReceiveFunc{func(packets [][]byte, sizes []int, _ []Endpoint) (int, error) {
		sizes[0] = copy(packets[0], []byte{0, 3, 4})
		sizes[1] = copy(packets[1], []byte{0, 2, 5, 6, 7})
		return 2, nil
	}}, port, nil
}

func TestHushivoBindBatch(t *testing.T) {
	underlying := new(framingTestBind)
	bind, err := NewHushivoBind(underlying, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{{1}, {2, 3}}, nil); err != nil {
		t.Fatal(err)
	}
	if len(underlying.sent) != 2 ||
		!bytes.Equal(underlying.sent[0], []byte{0, 1, 1}) ||
		!bytes.Equal(underlying.sent[1], []byte{0, 2, 2, 3}) {
		t.Fatalf("unexpected datagrams: %x", underlying.sent)
	}

	receivers, port, err := bind.Open(51820)
	if err != nil || port != 51820 {
		t.Fatalf("Open = port %d, error %v", port, err)
	}
	packets := [][]byte{make([]byte, 5), make([]byte, 5)}
	sizes := make([]int, 2)
	n, err := receivers[0](packets, sizes, make([]Endpoint, 2))
	if err != nil || n != 2 || sizes[0] != 0 || sizes[1] != 2 ||
		!bytes.Equal(packets[1][:sizes[1]], []byte{5, 6}) {
		t.Fatalf("unexpected receive result: n=%d sizes=%v packets=%x error=%v", n, sizes, packets, err)
	}
}
