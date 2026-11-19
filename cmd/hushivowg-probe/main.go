// Command hushivowg-probe performs an operator check through an isolated userspace
// tunnel. It changes no OS routes, creates no system TUN, and accepts secrets only
// on stdin. It never exports a proxy or listens for application traffic.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type configuration struct {
	PrivateKey      string `json:"privateKey"`
	ServerPublicKey string `json:"serverPublicKey"`
	Host            string `json:"host"`
	Port            uint16 `json:"port"`
	Address         string `json:"address"`
	ExpectedExit    string `json:"expectedExit"`
	ExpectRevoked   bool   `json:"expectRevoked"`
}
type result struct {
	Status           string `json:"status"`
	Error            string `json:"error,omitempty"`
	HandshakeSeconds uint64 `json:"handshakeSeconds,omitempty"`
	RXBytes          uint64 `json:"rxBytes,omitempty"`
	TXBytes          uint64 `json:"txBytes,omitempty"`
	ExitIPv4         string `json:"exitIpv4,omitempty"`
	DNSVerified      bool   `json:"dnsVerified"`
	HTTPSVerified    bool   `json:"httpsVerified"`
}

func keyHex(value string) (string, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 {
		return "", errors.New("INVALID_PROBE_KEY")
	}
	return hex.EncodeToString(raw), nil
}
func counters(dev *device.Device) (uint64, uint64, uint64) {
	text, err := dev.IpcGet()
	if err != nil {
		return 0, 0, 0
	}
	var handshake, rx, tx uint64
	for _, line := range strings.Split(text, "\n") {
		key, value, _ := strings.Cut(line, "=")
		n, _ := strconv.ParseUint(value, 10, 64)
		switch key {
		case "last_handshake_time_sec":
			handshake = n
		case "rx_bytes":
			rx = n
		case "tx_bytes":
			tx = n
		}
	}
	return handshake, rx, tx
}
func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HushivoWG-Probe/1")
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("PROBE_HTTP_STATUS")
	}
	return io.ReadAll(io.LimitReader(response.Body, 4096))
}
func run() (result, error) {
	var cfg configuration
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return result{}, errors.New("INVALID_PROBE_INPUT")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return result{}, errors.New("INVALID_PROBE_INPUT")
	}
	private, err := keyHex(cfg.PrivateKey)
	if err != nil {
		return result{}, err
	}
	public, err := keyHex(cfg.ServerPublicKey)
	if err != nil {
		return result{}, err
	}
	host, err := netip.ParseAddr(cfg.Host)
	if err != nil || !host.Is4() || cfg.Port == 0 {
		return result{}, errors.New("INVALID_PROBE_ENDPOINT")
	}
	address, err := netip.ParseAddr(cfg.Address)
	pool := netip.MustParsePrefix("10.66.0.0/20")
	if err != nil || !pool.Contains(address) || address == netip.MustParseAddr("10.66.0.1") {
		return result{}, errors.New("INVALID_PROBE_ADDRESS")
	}
	expected, err := netip.ParseAddr(cfg.ExpectedExit)
	if err != nil || !expected.Is4() {
		return result{}, errors.New("INVALID_EXPECTED_EXIT")
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{address}, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9")}, 1360)
	if err != nil {
		return result{}, errors.New("PROBE_NETSTACK_FAILED")
	}
	bind, err := conn.NewHushivoBind(conn.NewDefaultBind(), 1394)
	if err != nil {
		tun.Close()
		return result{}, errors.New("PROBE_FRAMING_FAILED")
	}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	ipc := "private_key=" + private + "\npublic_key=" + public + "\nendpoint=" + net.JoinHostPort(host.String(), strconv.Itoa(int(cfg.Port))) + "\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n"
	if dev.IpcSet(ipc) != nil || dev.Up() != nil {
		return result{}, errors.New("PROBE_DEVICE_FAILED")
	}
	timeout := 35 * time.Second
	if cfg.ExpectRevoked {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	transport := &http.Transport{DialContext: tnet.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("PROBE_REDIRECT_REJECTED") }}
	trace, requestError := get(ctx, client, "https://1.1.1.1/cdn-cgi/trace")
	handshake, rx, tx := counters(dev)
	if cfg.ExpectRevoked {
		if handshake != 0 || requestError == nil {
			return result{}, errors.New("REVOKED_PEER_STILL_RESPONDS")
		}
		return result{Status: "revocation_confirmed"}, nil
	}
	if requestError != nil {
		if handshake == 0 {
			return result{}, errors.New("EXTERNAL_HANDSHAKE_UNCONFIRMED")
		}
		return result{}, errors.New("TUNNEL_IP_EGRESS_FAILED")
	}
	var exit netip.Addr
	for _, line := range strings.Split(string(trace), "\n") {
		if strings.HasPrefix(line, "ip=") {
			exit, _ = netip.ParseAddr(strings.TrimPrefix(line, "ip="))
		}
	}
	if exit != expected {
		return result{}, errors.New("TUNNEL_EXIT_IP_MISMATCH")
	}
	resolved, err := tnet.LookupContextHost(ctx, "example.com")
	if err != nil || len(resolved) == 0 {
		return result{}, errors.New("TUNNEL_DNS_FAILED")
	}
	if _, err = get(ctx, client, "https://example.com/"); err != nil {
		return result{}, errors.New("TUNNEL_HTTPS_FAILED")
	}
	handshake, rx, tx = counters(dev)
	if handshake == 0 || rx == 0 || tx == 0 {
		return result{}, errors.New("TUNNEL_COUNTERS_UNCONFIRMED")
	}
	return result{Status: "connected", HandshakeSeconds: handshake, RXBytes: rx, TXBytes: tx, ExitIPv4: exit.String(), DNSVerified: true, HTTPSVerified: true}, nil
}
func main() {
	r, err := run()
	if err != nil {
		r = result{Status: "error", Error: err.Error()}
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
	if err != nil {
		os.Exit(1)
	}
}
