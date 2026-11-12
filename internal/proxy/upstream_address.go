package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

var errUpstreamAddressDenied = errors.New("upstream address is not allowed")

var publicIPv6Range = netip.MustParsePrefix("2000::/3")

// These special-purpose ranges need explicit checks beyond IsGlobalUnicast
// and IsPrivate. See the IANA IPv4 and IPv6 Special-Purpose Address Registries.
var blockedUpstreamRanges = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // this network
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4
	netip.MustParsePrefix("3fff::/20"),       // documentation
}

func isPublicUpstreamIP(ip netip.Addr) bool {
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || (ip.Is6() && !publicIPv6Range.Contains(ip)) {
		return false
	}
	for _, prefix := range blockedUpstreamRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// The dialer invokes this for each resolved IP before connecting to it.
// Checking at this point also covers fallback addresses and DNS rebinding.
func checkUpstreamAddress(_ context.Context, _, address string, _ syscall.RawConn) error {
	target, err := netip.ParseAddrPort(address)
	if err != nil || !isPublicUpstreamIP(target.Addr()) {
		return errUpstreamAddressDenied
	}

	// Public addresses assigned to this host can also expose local services.
	localAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("list local interface addresses: %w", err)
	}
	for _, local := range localAddrs {
		prefix, err := netip.ParsePrefix(local.String())
		if err != nil {
			return fmt.Errorf("invalid local interface address %q: %w", local, err)
		}
		if prefix.Addr().Unmap() == target.Addr().Unmap() {
			return errUpstreamAddressDenied
		}
	}
	return nil
}
