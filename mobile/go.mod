module github.com/hushivo/hushivowg-mobile

go 1.26.0

require (
	golang.org/x/mobile v0.0.0-20261117202452-47699113848a
	golang.org/x/sys v0.50.0
	golang.zx2c4.com/wireguard v0.0.0
)

require (
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace golang.zx2c4.com/wireguard => ..
