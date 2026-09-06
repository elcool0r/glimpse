package networkstate

import (
	"strings"

	"github.com/elcool0r/glimpse/internal/model"
)

const (
	maxNameservers   = 8
	maxSearchDomains = 16
	resolvConfPath   = "/etc/resolv.conf"
)

// stubAddresses are the loopback addresses systemd-resolved listens on. A host
// pointed only at these has delegated all name resolution to that service, so
// its failure takes DNS with it. A local dnsmasq or unbound on 127.0.0.1 is a
// different arrangement and is deliberately not matched here.
var stubAddresses = map[string]struct{}{"127.0.0.53": {}, "127.0.0.54": {}}

// ParseResolvConf reads the nameserver and search configuration. Options and
// unrecognized directives are ignored rather than reported: they cannot be
// judged correct or incorrect without knowing what the host is for.
func ParseResolvConf(raw string) model.DNSConfig {
	config := model.DNSConfig{Available: true}
	for _, line := range strings.Split(raw, "\n") {
		// A comment may start at any column, and resolv.conf accepts both
		// markers.
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			if len(config.Nameservers) < maxNameservers {
				config.Nameservers = append(config.Nameservers, fields[1])
			}
		case "search", "domain":
			// "domain" is the older single-value spelling of "search"; the
			// kernel resolver treats the last directive of either as the list.
			for _, domain := range fields[1:] {
				if len(config.SearchDomains) >= maxSearchDomains {
					break
				}
				config.SearchDomains = append(config.SearchDomains, domain)
			}
		}
	}
	config.StubResolver = onlyStubResolvers(config.Nameservers)
	return config
}

func onlyStubResolvers(nameservers []string) bool {
	if len(nameservers) == 0 {
		return false
	}
	for _, address := range nameservers {
		if _, ok := stubAddresses[address]; !ok {
			return false
		}
	}
	return true
}
