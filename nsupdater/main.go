package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

// TSIG (Transaction SIGnatures) as specified in RFC 2845
type TSIG struct {
	TSIGKey       string
	TSIGAlgorithm string
	TSIGSecret    string
}

// Config is the structure of the global Configuration object
type Config struct {
	Action     string
	IP         net.IP
	Hostname   string
	Zone       string
	Nameserver string
	TTL        int
	TSIG       TSIG
}

// DNSProvider is an implementation of the challenge.Provider interface that
// uses dynamic DNS updates (RFC 2136) to create TXT records on a nameserver.
type DNSProvider struct {
	config *Config
}

func (d *DNSProvider) printConfig() {
	fmt.Printf("%+v\n", d.config)
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
/*
	key string {
		algorithm string;
		secret string;
	};
*/
func parseBindKey(keyFilePath string) (tsig TSIG, err error) {
	content, err := ioutil.ReadFile(keyFilePath)
	keyText := string(content)
	re := regexp.MustCompile(`key\s+"(?P<keyname>[^"]+)"\s+{\n?\s+algorithm\s+(?P<alg>[^;]+);\n?\s+secret\s+"(?P<secret>[^"]+)";\n?};`)

	tsigString := re.FindStringSubmatch(keyText)
	if tsigString == nil {
		err = errors.New("Could not parse keyfile")
		return
	}

	switch tsigString[2] {
	case "hmac-md5":
		tsig = TSIG{tsigString[1], "hmac-md5.sig-alg.reg.int.", tsigString[3]}
	case "hmac-sha1":
		tsig = TSIG{tsigString[1], "hmac-sha1.", tsigString[3]}
	case "hmac-sha256":
		tsig = TSIG{tsigString[1], "hmac-sha256.", tsigString[3]}
	}
	return
}

func getDefaultIP() (ip string) {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			return ip.String()
		}
	}
	return
}

func getDefautHostname() (hostname string) {
	hostname, _ = os.Hostname()
	return hostname
}

func (d *DNSProvider) changeRecord() error {
	zone := d.config.Zone
	fqdn := d.config.Hostname
	ip := d.config.IP

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
	if len(d.config.TSIG.TSIGKey) > 0 && len(d.config.TSIG.TSIGSecret) > 0 {
		m.SetTsig(dns.Fqdn(d.config.TSIG.TSIGKey), d.config.TSIG.TSIGAlgorithm, 300, time.Now().Unix())
		c.TsigSecret = map[string]string{dns.Fqdn(d.config.TSIG.TSIGKey): d.config.TSIG.TSIGSecret}
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

func sanitizeConfig(action string, ip string, hostname string, zone string, nameserver string, nsPort int, tsigFile string, ttl int) (config Config, err error) {
	if !(stringInSlice(action, []string{"add", "delete", "update"})) {
		err = errors.New("Action, either 'add', 'delete' or 'update' [default: update]")
	}
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		err = fmt.Errorf("ip: %q is not a valid IPv4 IP", ip)
	}
	if config.Hostname == "" {
		err = errors.New("could not get hostname")
	}
	if config.Zone == "" {
		err = errors.New("Set a zone [--zone ] or env NSUPDATE_ZONE")
	}
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, strconv.Itoa(nsPort))
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + strconv.Itoa(nsPort)
	}
	_, err = os.Stat(tsigFile)
	tsig, err := parseBindKey(tsigFile)

	config = Config{action, ipAddr, hostname, dns.Fqdn(zone), nameserver, ttl, tsig}
	return
}

func newDNSClient(config Config) (*DNSProvider, error) {
	var provider = DNSProvider{&config}
	return &provider, nil
}

func main() {
	var (
		action     string
		ip         string
		hostname   string
		nameserver string
		nsPort     int
		zone       string
		tsigFile   string
		ttl        int
		debug      bool
		err        error
	)

	flag.StringVar(&action, "action", "update", "Action, either 'add', 'delete' or 'update' [default: update]")
	flag.StringVar(&ip, "ip", getDefaultIP(), "Client IP Adress")
	flag.StringVar(&hostname, "hostname", getDefautHostname(), "Client Hostname")
	flag.StringVar(&nameserver, "nameserver", "127.0.0.1", "Nameserver to send the update to [default: 127.0.0.1]")
	flag.IntVar(&nsPort, "nsport", 53, "Port of the Nameserver to send the update to [default: 53]")
	flag.StringVar(&zone, "zone", os.Getenv("NSUPDATE_ZONE"), "DNS Zone to Add A Record for the Client")
	flag.IntVar(&ttl, "ttl", 600, "RR TTL")
	flag.StringVar(&tsigFile, "tsigFile", "/etc/rndc.key", "File holding the tsig key")

	flag.BoolVar(&debug, "debug", false, "Run in Debug mode")
	flag.Parse()

	config, err := sanitizeConfig(action, ip, hostname, zone, nameserver, nsPort, tsigFile, ttl)
	if err != nil {
		panic(err)
	}

	dnsclient, err := newDNSClient(config)
	if err != nil {
		panic(err)
	}
	if debug {
		dnsclient.printConfig()
	}

	err = dnsclient.changeRecord()
	if err != nil {
		panic(err)
	}
}
