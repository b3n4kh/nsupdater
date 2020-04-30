package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

// TSIG (Transaction SIGnatures) as specified in RFC 2845
type TSIG struct {
	TSIGAlgorithm string
	TSIGKey       string
	TSIGSecret    string
}

// Config is the structure of the global Configuration object
type Config struct {
	Action      string
	IP          string
	Hostname    string
	ForwardZone string
	ReverseZone string
	Nameserver  string
	TSIGFile    string
	TTL         int
	TSIG        TSIG
}

// DNSProvider is an implementation of the challenge.Provider interface that
// uses dynamic DNS updates (RFC 2136) to create TXT records on a nameserver.
type DNSProvider struct {
	config *Config
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func isIpv4(host string) bool {
	return net.ParseIP(host) != nil
}

// Parse Key as defined at https://ftp.isc.org/isc/bind/9.11.4/doc/arm/Bv9ARM.ch06.html#key_grammar
func parseBindKey(keyFilePath string) (tsig TSIG, err error) {
	err = nil
	return
}

// GetRecord returns a DNS record which will fulfill the `dns-01` challenge
func getRecord(domain, keyAuth string) (fqdn string, value string) {
	keyAuthShaBytes := sha256.Sum256([]byte(keyAuth))
	// base64URL encoding without padding
	value = base64.RawURLEncoding.EncodeToString(keyAuthShaBytes[:sha256.Size])
	fqdn = fmt.Sprintf("_acme-challenge.%s.", domain)

	if ok, _ := strconv.ParseBool(os.Getenv("CNAME")); ok {
		r, err := dnsQuery(fqdn, dns.TypeCNAME, recursiveNameservers, true)
		// Check if the domain has CNAME then return that
		if err == nil && r.Rcode == dns.RcodeSuccess {
			fqdn = updateDomainWithCName(r, fqdn)
		}
	}

	return
}

// Present creates a A record using the specified parameters
func (d *DNSProvider) present(domain, token, keyAuth string) error {
	fqdn, value := getRecord(domain, keyAuth)

	err := d.changeRecord("INSERT", fqdn, value, d.config.TTL)
	if err != nil {
		return fmt.Errorf("rfc2136: failed to insert: %w", err)
	}
	return nil
}

// CleanUp removes the A record matching the specified parameters
func (d *DNSProvider) cleanUp(domain, token, keyAuth string) error {
	fqdn, value := getRecord(domain, keyAuth)

	err := d.changeRecord("REMOVE", fqdn, value, d.config.TTL)
	if err != nil {
		return fmt.Errorf("rfc2136: failed to remove: %w", err)
	}
	return nil
}

func (d *DNSProvider) changeRecord(fqdn string, ip net.IP) error {
	// Find the zone for the given fqdn
	zone := d.config.ForwardZone

	// Create RR
	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(d.config.TTL)}
	rr.A = ip
	rrs := []dns.RR{rr}

	// Create dynamic update packet
	m := new(dns.Msg)
	m.SetUpdate(zone)
	m.RemoveRRset(rrs)
	// 		m.Remove(rrs) ?
	m.Insert(rrs)

	// Setup client
	c := &dns.Client{Timeout: 10 * time.Second}
	c.SingleInflight = true

	// TSIG authentication / msg signing
	if len(d.config.TSIGKey) > 0 && len(d.config.TSIGSecret) > 0 {
		m.SetTsig(dns.Fqdn(d.config.TSIGKey), d.config.TSIGAlgorithm, 300, time.Now().Unix())
		c.TsigSecret = map[string]string{dns.Fqdn(d.config.TSIGKey): d.config.TSIGSecret}
	}

	// Send the query
	reply, _, err := c.Exchange(m, d.config.Nameserver)
	if err != nil {
		return fmt.Errorf("DNS update failed: %w", err)
	}
	if reply != nil && reply.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS update failed: server replied: %s", dns.RcodeToString[reply.Rcode])
	}

	return nil
}

func sanitizeConfig(config Config) error {
	var actions = []string{"add", "delete", "update"}
	if !(stringInSlice(config.Action, actions)) {
		return errors.New("Action, either 'add', 'delete' or 'update' [default: update]")
	}
	if !(isIpv4(config.IP)) {
		return errors.New("ip is not a valid IPv4 IP")
	}
	if !(isIpv4(config.Nameserver)) {
		return errors.New("nameserver is not a valid IPv4 IP")
	}
	if config.Hostname == "" || config.ForwardZone == "" || config.ReverseZone == "" {
		return errors.New("please set hostname, forwadzone and reversezone")
	}

	return nil
}

func updateDNS(config Config) error {
	return nil
}

func main() {
	var (
		action      string
		ip          string
		hostname    string
		nameserver  string
		forwardZone string
		reverseZone string
		tsigFile    string
		ttl         int
		debug       bool
		err         error
	)

	flag.StringVar(&action, "action", "update", "Action, either 'add', 'delete' or 'update' [default: update]")
	flag.StringVar(&ip, "ip", "", "Client IP Adress")
	flag.StringVar(&hostname, "hostname", "", "Client Hostname")
	flag.StringVar(&nameserver, "nameserver", "127.0.0.1", "Nameserver to send the update to [default: 127.0.0.1]")
	flag.StringVar(&forwardZone, "forwardZone", "", "DNS Zone to Add A Record for the Client")
	flag.IntVar(&ttl, "ttl", 600, "RR TTL")
	flag.StringVar(&reverseZone, "reverseZone", "", "DNS ReverseZone to Add PTR Record for the Client")
	flag.StringVar(&tsigFile, "tsigFile", "", "File holding the tsig key")

	flag.BoolVar(&debug, "debug", false, "Run in Debug mode")
	flag.Parse()

	var config = Config{action, ip, hostname, forwardZone, reverseZone, nameserver, tsigFile, ttl, nil}
	err = sanitizeConfig(config)
	if err != nil {
		panic(err)
	}
	err = updateDNS(config)
	if err != nil {
		panic(err)
	}
}
