/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

func (b *HushivoBind) PeekLookAtSocketFd4() (int, error) {
	if sockets, ok := b.Bind.(PeekLookAtSocketFd); ok {
		return sockets.PeekLookAtSocketFd4()
	}
	return -1, ErrWrongEndpointType
}

func (b *HushivoBind) PeekLookAtSocketFd6() (int, error) {
	if sockets, ok := b.Bind.(PeekLookAtSocketFd); ok {
		return sockets.PeekLookAtSocketFd6()
	}
	return -1, ErrWrongEndpointType
}

func (s *StdNetBind) PeekLookAtSocketFd4() (fd int, err error) {
	sysconn, err := s.ipv4.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}

func (s *StdNetBind) PeekLookAtSocketFd6() (fd int, err error) {
	sysconn, err := s.ipv6.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}
