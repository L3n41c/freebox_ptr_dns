package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	ipv4Suffix = "in-addr.arpa"
	ipv6Suffix = "ip6.arpa"
)

// AddrFromPTR parses a PTR query name (e.g. "42.1.168.192.in-addr.arpa.")
// into the netip.Addr it points to (192.168.1.42 in this example).
// Trailing dot and case are tolerated.
func AddrFromPTR(qname string) (netip.Addr, error) {
	if qname == "" {
		return netip.Addr{}, errors.New("empty qname")
	}
	name := strings.ToLower(strings.TrimSuffix(qname, "."))

	switch {
	case strings.HasSuffix(name, "."+ipv4Suffix):
		return parseIPv4Arpa(strings.TrimSuffix(name, "."+ipv4Suffix))
	case strings.HasSuffix(name, "."+ipv6Suffix):
		return parseIPv6Arpa(strings.TrimSuffix(name, "."+ipv6Suffix))
	default:
		return netip.Addr{}, fmt.Errorf("not an arpa name: %q", qname)
	}
}

func parseIPv4Arpa(prefix string) (netip.Addr, error) {
	labels := strings.Split(prefix, ".")
	if len(labels) != 4 {
		return netip.Addr{}, fmt.Errorf("ipv4 arpa: expected 4 labels, got %d", len(labels))
	}
	var octets [4]byte
	for i, l := range labels {
		n, err := strconv.Atoi(l)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("ipv4 arpa: label %q: %w", l, err)
		}
		if n < 0 || n > 255 {
			return netip.Addr{}, fmt.Errorf("ipv4 arpa: octet %d out of range", n)
		}
		octets[3-i] = byte(n)
	}
	return netip.AddrFrom4(octets), nil
}

func parseIPv6Arpa(prefix string) (netip.Addr, error) {
	labels := strings.Split(prefix, ".")
	if len(labels) != 32 {
		return netip.Addr{}, fmt.Errorf("ipv6 arpa: expected 32 nibbles, got %d", len(labels))
	}
	var bytes [16]byte
	for i, l := range labels {
		if len(l) != 1 {
			return netip.Addr{}, fmt.Errorf("ipv6 arpa: nibble %q invalid length", l)
		}
		n, err := strconv.ParseUint(l, 16, 8)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("ipv6 arpa: nibble %q: %w", l, err)
		}
		// labels are reversed: index 0 is least-significant nibble of the last byte.
		pos := 15 - i/2
		if i%2 == 0 {
			bytes[pos] = byte(n)
		} else {
			bytes[pos] |= byte(n) << 4
		}
	}
	return netip.AddrFrom16(bytes), nil
}
