package host

import (
	"net"
	"os"
)

type Info struct {
	Hostname string
	IPv4     string
	IPv6     string
}

func Detect() Info {
	hostname, _ := os.Hostname()
	info := Info{Hostname: hostname}
	ifaces, err := net.Interfaces()
	if err != nil {
		return info
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if info.IPv4 == "" {
					info.IPv4 = ip4.String()
				}
				continue
			}
			if ip.To16() != nil && info.IPv6 == "" {
				info.IPv6 = ip.String()
			}
		}
		if info.IPv4 != "" && info.IPv6 != "" {
			break
		}
	}
	return info
}
