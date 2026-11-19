//go:build android

// Package hushivowg binds the HushivoWG userspace engine to Android VpnService.
package hushivowg

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type Protector interface{ ProtectSocket(fd int32) bool }
type Tunnel struct {
	mu                sync.Mutex
	dev               *device.Device
	peer              device.NoisePublicKey
	requiredHandshake int64
}

var lifecycle sync.Mutex
var active *Tunnel

type settings struct {
	PrivateKey          string `json:"privateKey"`
	ServerPublicKey     string `json:"serverPublicKey"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	UDPBudget           int    `json:"udpBudget"`
	MTU                 int    `json:"mtu"`
	PersistentKeepalive int    `json:"persistentKeepalive"`
}

func rawKey(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("HUSHIVOWG_INVALID_KEY")
	}
	return raw, nil
}

// Start duplicates the Android TUN descriptor. Go owns only the duplicate;
// VpnService retains and closes its ParcelFileDescriptor independently.
func Start(fd int64, config string, protector Protector) (*Tunnel, error) {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if active != nil {
		return nil, errors.New("HUSHIVOWG_ALREADY_RUNNING")
	}
	if protector == nil || fd < 0 || fd > 2147483647 {
		return nil, errors.New("HUSHIVOWG_INVALID_TUN")
	}
	var cfg settings
	if json.Unmarshal([]byte(config), &cfg) != nil {
		return nil, errors.New("HUSHIVOWG_INVALID_CONFIG")
	}
	host, err := netip.ParseAddr(cfg.Host)
	if err != nil || !host.Is4() || cfg.Port < 1 || cfg.Port > 65535 || cfg.MTU != 1360 || cfg.UDPBudget != 1394 || cfg.PersistentKeepalive != 25 {
		return nil, errors.New("HUSHIVOWG_INVALID_CONFIG")
	}
	private, err := rawKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	public, err := rawKey(cfg.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	duplicate, err := unix.Dup(int(fd))
	if err != nil {
		return nil, errors.New("HUSHIVOWG_DUP_TUN_FAILED")
	}
	tunnel, _, err := tun.CreateUnmonitoredTUNFromFD(duplicate)
	if err != nil {
		unix.Close(duplicate)
		return nil, errors.New("HUSHIVOWG_TUN_FAILED")
	}
	conn.SetAndroidSocketProtector(protector.ProtectSocket)
	bind, err := conn.NewHushivoBind(conn.NewDefaultBind(), cfg.UDPBudget)
	if err != nil {
		tunnel.Close()
		conn.SetAndroidSocketProtector(nil)
		return nil, errors.New("HUSHIVOWG_BIND_FAILED")
	}
	dev := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelSilent, ""))
	dev.DisableSomeRoamingForBrokenMobileSemantics()
	value := &Tunnel{dev: dev, requiredHandshake: time.Now().UnixNano()}
	copy(value.peer[:], public)
	ipc := "private_key=" + hex.EncodeToString(private) + "\npublic_key=" + hex.EncodeToString(public) + "\nendpoint=" + net.JoinHostPort(host.String(), strconv.Itoa(cfg.Port)) + "\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n"
	if dev.IpcSet(ipc) != nil || dev.Up() != nil {
		dev.Close()
		conn.SetAndroidSocketProtector(nil)
		return nil, errors.New("HUSHIVOWG_START_FAILED")
	}
	active = value
	if peer := dev.LookupPeer(value.peer); peer != nil {
		_ = peer.SendHandshakeInitiation(false)
	}
	return value, nil
}
func (t *Tunnel) Reconnect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev == nil {
		return errors.New("HUSHIVOWG_CLOSED")
	}
	t.requiredHandshake = time.Now().UnixNano()
	if t.dev.BindUpdate() != nil {
		return errors.New("HUSHIVOWG_REBIND_FAILED")
	}
	peer := t.dev.LookupPeer(t.peer)
	if peer == nil {
		return errors.New("HUSHIVOWG_PEER_MISSING")
	}
	if peer.SendHandshakeInitiation(false) != nil {
		return errors.New("HUSHIVOWG_HANDSHAKE_SEND_FAILED")
	}
	return nil
}

// Status returns counters and connection state only, never UAPI private keys.
func (t *Tunnel) Status() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	inactive := `{"active":false,"connected":false}`
	if t.dev == nil {
		return inactive
	}
	select {
	case <-t.dev.Wait():
		return inactive
	default:
	}
	value, err := t.dev.IpcGet()
	if err != nil {
		return inactive
	}
	var seconds, nanos, rx, tx int64
	for _, line := range strings.Split(value, "\n") {
		key, text, _ := strings.Cut(line, "=")
		number, _ := strconv.ParseInt(text, 10, 64)
		switch key {
		case "last_handshake_time_sec":
			seconds = number
		case "last_handshake_time_nsec":
			nanos = number
		case "rx_bytes":
			rx = number
		case "tx_bytes":
			tx = number
		}
	}
	handshake := seconds*int64(time.Second) + nanos
	bytes, _ := json.Marshal(map[string]any{"active": true, "connected": handshake > 0 && handshake >= t.requiredHandshake, "handshakeMillis": handshake / int64(time.Millisecond), "rxBytes": rx, "txBytes": tx})
	return string(bytes)
}
func (t *Tunnel) Close() {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
	}
	if active == t {
		active = nil
		conn.SetAndroidSocketProtector(nil)
	}
}
