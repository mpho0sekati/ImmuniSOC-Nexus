package netutil

import (
	"net"
	"net/http"
	"os"
	"strings"
)

const defaultTrustedProxyCIDRs = "127.0.0.1/32,::1/128"

// ClientIP returns the caller IP. Forwarded headers are honored only when the
// direct peer is a configured trusted proxy.
func ClientIP(r *http.Request) string {
	return ClientIPWithTrustedCIDRs(r, TrustedProxyCIDRsFromEnv())
}

func ClientIPWithTrustedCIDRs(r *http.Request, trustedCIDRs []*net.IPNet) string {
	remoteIP := remoteAddressIP(r.RemoteAddr)
	if remoteIP == nil {
		return ""
	}

	if isTrustedProxy(remoteIP, trustedCIDRs) {
		if forwarded := firstHeaderIP(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			return forwarded
		}
		if realIP := firstHeaderIP(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}

	return remoteIP.String()
}

func TrustedProxyCIDRsFromEnv() []*net.IPNet {
	value := strings.TrimSpace(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if value == "" {
		value = defaultTrustedProxyCIDRs
	}
	return ParseCIDRs(value)
}

func ParseCIDRs(value string) []*net.IPNet {
	var cidrs []*net.IPNet
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(part)
		if err == nil {
			cidrs = append(cidrs, cidr)
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			cidrs = append(cidrs, &net.IPNet{IP: ip, Mask: mask})
		}
	}
	return cidrs
}

func remoteAddressIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func firstHeaderIP(value string) string {
	for _, part := range strings.Split(value, ",") {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip != nil {
			return ip.String()
		}
	}
	return ""
}

func isTrustedProxy(ip net.IP, trustedCIDRs []*net.IPNet) bool {
	for _, cidr := range trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
