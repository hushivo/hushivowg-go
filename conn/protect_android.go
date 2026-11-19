//go:build android

package conn

import (
	"errors"
	"sync"
	"syscall"
)

var androidProtect struct {
	sync.RWMutex
	callback func(int32) bool
}

// SetAndroidSocketProtector configures VpnService.protect for every new bind
// socket, including sockets recreated after a physical network change.
// The mobile backend owns a single active tunnel and clears it after Close.
func SetAndroidSocketProtector(callback func(int32) bool) {
	androidProtect.Lock()
	androidProtect.callback = callback
	androidProtect.Unlock()
}
func init() {
	controlFns = append(controlFns, func(_ string, _ string, raw syscall.RawConn) error {
		androidProtect.RLock()
		callback := androidProtect.callback
		androidProtect.RUnlock()
		if callback == nil {
			return errors.New("HUSHIVOWG_SOCKET_PROTECTOR_REQUIRED")
		}
		ok := false
		if err := raw.Control(func(fd uintptr) { ok = callback(int32(fd)) }); err != nil {
			return err
		}
		if !ok {
			return errors.New("HUSHIVOWG_SOCKET_PROTECTION_FAILED")
		}
		return nil
	})
}
