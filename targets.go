package divert

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// TargetRule limits eligible destinations before process lookup. IPs accepts
// literal IPv4/IPv6 addresses and CIDRs; Ports accepts decimal ports or inclusive
// ranges such as "8000-8100". Empty fields match any IP or port. Fields within a
// rule are ANDed; rules are ORed. Hostnames and wildcard strings are not accepted.
type TargetRule struct {
	IPs   []string `json:"ips,omitempty"`
	Ports []string `json:"ports,omitempty"`
}

type portRange struct{ first, last uint16 }
type targetRule struct {
	ips   []netip.Prefix
	ports []portRange
}
type targetSet struct {
	rules  []targetRule
	filter string
}

func compileTargets(rules []TargetRule) (targetSet, error) {
	set := targetSet{filter: "true"}
	if len(rules) > 32 {
		return set, fmt.Errorf("targets supports at most 32 rules")
	}
	var expressions []string
	selectors := 0
	for i, rule := range rules {
		selectors += len(rule.IPs) + len(rule.Ports)
		if selectors > 64 {
			return set, fmt.Errorf("targets supports at most 64 IP/port selectors")
		}
		var compiled targetRule
		var ips, ports []string
		for _, value := range rule.IPs {
			var prefix netip.Prefix
			var err error
			if strings.Contains(value, "/") {
				prefix, err = netip.ParsePrefix(value)
			} else {
				var addr netip.Addr
				addr, err = netip.ParseAddr(value)
				if err == nil {
					prefix = netip.PrefixFrom(addr, addr.BitLen())
				}
			}
			if strings.Contains(value, "%") || err != nil || !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
				return set, fmt.Errorf("targets[%d]: invalid IP or CIDR %q (use native IPv4/IPv6, without zones)", i, value)
			}
			prefix = prefix.Masked()
			compiled.ips = append(compiled.ips, prefix)
			first := prefix.Addr()
			bytes := append([]byte(nil), first.AsSlice()...)
			for bit := prefix.Bits(); bit < len(bytes)*8; bit++ {
				bytes[bit/8] |= 1 << uint(7-bit%8)
			}
			last, _ := netip.AddrFromSlice(bytes)
			family, field := "ip", "ip.DstAddr"
			if first.Is6() {
				family, field = "ipv6", "ipv6.DstAddr"
			}
			if first == last {
				ips = append(ips, fmt.Sprintf("(%s and %s == %s)", family, field, first))
			} else {
				ips = append(ips, fmt.Sprintf("(%s and %s >= %s and %s <= %s)", family, field, first, field, last))
			}
		}
		for _, value := range rule.Ports {
			parts := strings.Split(value, "-")
			parse := func(s string) (uint16, error) {
				if s == "" || strings.Trim(s, "0123456789") != "" {
					return 0, fmt.Errorf("not a decimal port")
				}
				n, err := strconv.ParseUint(s, 10, 16)
				if err != nil || n == 0 {
					return 0, fmt.Errorf("port must be 1..65535")
				}
				return uint16(n), nil
			}
			if len(parts) > 2 {
				return set, fmt.Errorf("targets[%d]: invalid port range %q", i, value)
			}
			first, err := parse(parts[0])
			last := first
			if err == nil && len(parts) == 2 {
				last, err = parse(parts[1])
			}
			if err != nil || first > last {
				return set, fmt.Errorf("targets[%d]: invalid port or range %q", i, value)
			}
			compiled.ports = append(compiled.ports, portRange{first, last})
			if first == last {
				ports = append(ports, fmt.Sprintf("tcp.DstPort == %d", first))
			} else {
				ports = append(ports, fmt.Sprintf("(tcp.DstPort >= %d and tcp.DstPort <= %d)", first, last))
			}
		}
		ipExpr, portExpr := "true", "true"
		if len(ips) > 0 {
			ipExpr = strings.Join(ips, " or ")
		}
		if len(ports) > 0 {
			portExpr = strings.Join(ports, " or ")
		}
		expressions = append(expressions, "(("+ipExpr+") and ("+portExpr+"))")
		set.rules = append(set.rules, compiled)
	}
	if len(expressions) > 0 {
		set.filter = strings.Join(expressions, " or ")
	}
	return set, nil
}

func (s targetSet) matches(target netip.AddrPort) bool {
	if len(s.rules) == 0 {
		return true
	}
	for _, r := range s.rules {
		ipOK, portOK := len(r.ips) == 0, len(r.ports) == 0
		for _, prefix := range r.ips {
			if prefix.Contains(target.Addr()) {
				ipOK = true
				break
			}
		}
		for _, ports := range r.ports {
			if target.Port() >= ports.first && target.Port() <= ports.last {
				portOK = true
				break
			}
		}
		if ipOK && portOK {
			return true
		}
	}
	return false
}

func (c Config) packetFilter() string {
	// Relay replies carry the original remote address but a translated destination
	// port. They must reach the reverse map even when the target port is restricted.
	// Other drivers may reinject packets after a connection is established.
	// Those packets still need both directions of an existing NAT mapping.
	return fmt.Sprintf("outbound and tcp and !loopback and ((%s) or tcp.SrcPort == %d)", c.targets.filter, c.RelayPort)
}
