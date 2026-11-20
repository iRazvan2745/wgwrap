// Package userspace runs wireguard-go in-process and supervises the app as PID 1.
package userspace

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

// Device is an in-process WireGuard interface backed by a TUN device.
type Device struct {
	dev  *device.Device
	uapi net.Listener
}

// Start creates the TUN interface and exposes the UAPI socket so wgctrl can configure it
// exactly like a kernel interface.
func Start(name string, mtu int, debug bool) (*Device, error) {
	// Checked up front: wireguard-go's error for this case doesn't wrap fs.ErrNotExist.
	if _, err := os.Stat("/dev/net/tun"); errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("userspace mode needs /dev/net/tun, which doesn't exist in this container; add --device /dev/net/tun")
	}
	t, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("userspace mode: create TUN %s: %w", name, err)
	}
	level := device.LogLevelError
	if debug {
		level = device.LogLevelVerbose
	}
	d := &Device{dev: device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(level, "wgwrap: wireguard-go: "))}
	f, err := ipc.UAPIOpen(name)
	if err != nil {
		d.dev.Close()
		return nil, fmt.Errorf("userspace mode: create UAPI socket in /var/run/wireguard: %w (is the root filesystem read-only? add --tmpfs /var/run/wireguard)", err)
	}
	if d.uapi, err = ipc.UAPIListen(name, f); err != nil {
		d.dev.Close()
		return nil, fmt.Errorf("userspace mode: listen on UAPI socket: %w", err)
	}
	go func() {
		for {
			c, err := d.uapi.Accept()
			if err != nil {
				return
			}
			go d.dev.IpcHandle(c)
		}
	}()
	return d, nil
}

// CloseUAPI removes the control socket once configuration is done, so the app (which may
// still be root) can't reconfigure the tunnel through it.
func (d *Device) CloseUAPI() { d.uapi.Close() }

// Done is closed when the device shuts down (e.g. the TUN interface was deleted).
func (d *Device) Done() <-chan struct{} { return d.dev.Wait() }
