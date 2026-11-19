// SPDX-License-Identifier: MIT

package conn

import "golang.zx2c4.com/wireguard/internal/framing"

// HushivoBind wraps all messages sent through a UDP bind in HushivoWG v1.
// Both endpoints must use the same format.
type HushivoBind struct {
	Bind
	format framing.V1
}

func NewHushivoBind(bind Bind, budget int) (*HushivoBind, error) {
	format, err := framing.NewV1(budget)
	if err != nil {
		return nil, err
	}
	return &HushivoBind{Bind: bind, format: format}, nil
}

func (b *HushivoBind) Send(messages [][]byte, endpoint Endpoint) error {
	datagrams := make([][]byte, len(messages))
	for i, message := range messages {
		datagram, err := b.format.Encode(message, nil)
		if err != nil {
			return err
		}
		datagrams[i] = datagram
	}
	return b.Bind.Send(datagrams, endpoint)
}

func (b *HushivoBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	receivers, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, actualPort, err
	}
	wrapped := make([]ReceiveFunc, len(receivers))
	for i, receive := range receivers {
		wrapped[i] = func(packets [][]byte, sizes []int, endpoints []Endpoint) (int, error) {
			n, err := receive(packets, sizes, endpoints)
			if err != nil {
				return n, err
			}
			for j := 0; j < n; j++ {
				message, err := b.format.Decode(packets[j][:sizes[j]])
				if err != nil {
					sizes[j] = 0
					continue
				}
				sizes[j] = copy(packets[j], message)
			}
			return n, nil
		}
	}
	return wrapped, actualPort, nil
}
