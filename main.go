package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
)

var cgnat []net.IPNet = make([]net.IPNet, 0)

func init() {
	// log handler to file and console out
	logFile, err := os.OpenFile("logfile.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		panic(err)
	}
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile) // | log.Lmicroseconds  )
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)

	r := []net.IPNet{}
	ranges := []string{
		"0.0.0.0/32",         // Current network (only valid as source address)
		"240.0.0.0/4",        // Reserved for future use
		"203.0.113.0/24",     // Assigned as TEST-NET-3
		"198.51.100.0/24",    // Assigned as TEST-NET-2, documentation and examples
		"198.18.0.0/15",      // Used for benchmark testing of inter-network communications between two separate subnets
		"192.0.2.0/24",       // Assigned as TEST-NET-1, documentation and examples
		"100.64.0.0/10",      // Shared address space for communications between a service provider and its subscribers when using a carrier-grade NAT.
		"255.255.255.255/32", // Reserved for the "limited broadcast" destination address
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // Assigned as TEST-NET-1, documentation and examples
		"192.88.99.0/24",     // Reserved. Formerly used for IPv6 to IPv4 relay (included IPv6 address block 2002::/16)
		"192.168.0.0/16",     // Used for local communications within a private network
		"172.16.0.0/12",      // Used for local communications within a private network
		"10.0.0.0/8",         // Used for local communications within a private network
		"127.0.0.0/8",        // Used for loopback addresses to the local host
		"169.254.0.0/16",     // Used for link-local addresses between two hosts on a single link when no IP address is otherwise specified
		"224.0.0.0/4",        // In use for IP multicast.[9] (Former Class D network)
	}

	for _, sCIDR := range ranges {
		_, c, _ := net.ParseCIDR(sCIDR)
		r = append(r, *c)
	}
	cgnat = r
}

func main() {
	fmt.Println("Start Check")
	out, err := exec.Command("tracert", "-4", "8.8.8.8").Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(out))

	filter := regexp.MustCompile(`^\s{1,}\d{1,}\s{1,}([<>]|)\d{1,}\s{1,}ms\s{1,}([<>]|)\d{1,}\sms\s{1,}([<>]|)\d{1,}\sms\s{1,}.{1,}\s$`)
	cutset := regexp.MustCompile(`^\s{1,}\d{1,}\s{1,}([<>]|)\d{1,}\s{1,}ms\s{1,}([<>]|)\d{1,}\sms\s{1,}([<>]|)\d{1,}\sms\s{1,}`)

	var hops []string = make([]string, 0)
	for _, v := range strings.Split(string(out), "\n") {
		if filter.MatchString(v) {
			addr := strings.TrimSpace(cutset.ReplaceAllString(v, ""))
			addr = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`).FindAllString(addr, -1)[0]
			if ip := net.ParseIP(addr); ip != nil {
				hops = append(hops, ip.String())
			}
		}
	}

	fmt.Println(hops)

	/* req, err := http.Get(`https://api4.my-ip.io/ip.json`)
	if err != nil {
		log.Fatal(err)
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Fatal(err)
	}
	var data struct {
		Success bool   `json:"success"`
		IP      string `json:"ip"`
		IPType  string `json:"type"`
	}
	json.Unmarshal(body, &data) */

	var matches int = 0
	for _, v := range hops[1:] {
		if IsCGNAT(net.ParseIP(v)) {
			matches += 1
		}
	}
	if matches > 0 {
		fmt.Println("you have CGNAT you cant host any servers on your IPv4 or no IPv4 at all", hops[1:])
	} else {
		fmt.Println("your connection is not CGNAT you maybe can host")
	}

	// Wait here until CTRL-C or other term signal is received.
	fmt.Println("Press CTRL-C to exit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
}

func IsCGNAT(ip net.IP) bool {
	for _, r := range cgnat {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
