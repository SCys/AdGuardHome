package worker

import (
	"bytes"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/dnsfilter"
	"github.com/miekg/dns"
)

const (
	queueSize       = 1000            // size chan
	elapsedMaxLimit = 1 * time.Second // ignored over
)

var manager = RuleManager{}

var queueDefault chan string

// ProcessDNSResult process the result
func ProcessDNSResult(result *dnsfilter.Result, resp *dns.Msg) {
	if len(resp.Answer) == 0 {
		return
	}

	if result.IsFiltered || result.Reason != dnsfilter.NotFilteredWhiteList {
		return
	}

	// log.Printf("worker:%d", result.FilterID)

	if result.FilterID < 10 {
		return
	}

	var domain, ip string
	for _, answer := range resp.Answer {
		domain = strings.ToLower(answer.Header().Name)
		domain = domain[:len(domain)-1] // remove last "."

		switch answer.Header().Rrtype {
		case dns.TypeA:
			ip = answer.(*dns.A).A.String()
		// TODO support AAA
		// case dns.TypeAAAA:
		// ip = answer.(*dns.AAAA).AAAA.String()
		default:
			continue
		}

		cmd := exec.Command("nft", "add", "element", "gfw", "temp", "{", ip, "timeout", "30m", "}")

		var buf bytes.Buffer
		cmd.Stderr = &buf

		err := cmd.Run()
		if err != nil {
			log.Printf("cmd error:%d %s=>%s do %s %s", result.FilterID, domain, ip, err.Error(), buf.String())
		} else {
			log.Printf("cmd:%d %s=>%s", result.FilterID, domain, ip)
		}
	}
}
