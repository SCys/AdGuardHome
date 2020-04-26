package worker

import (
	"bytes"
	"os/exec"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/dnsfilter"
	"github.com/AdguardTeam/golibs/log"
	"github.com/karlseguin/ccache"
	"github.com/miekg/dns"
)

const (
	queueSize       = 1000            // size chan
	elapsedMaxLimit = 1 * time.Second // ignored over
)

var (
	cache        = ccache.New(ccache.Configure().MaxSize(1000).ItemsToPrune(100))
	manager      = RuleManager{}
	queueDefault chan string
)

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

			if item := cache.Get(ip); item != nil {
				log.Debug("ignore:%s=>%s", domain, ip)
				continue
			}

		// TODO support AAA
		// case dns.TypeAAAA:
		// ip = answer.(*dns.AAAA).AAAA.String()
		default:
			continue
		}

		cmd := exec.Command("nft", "add", "element", "gfw", "temp", "{", ip, "timeout", "15m", "}")

		var buf bytes.Buffer
		cmd.Stderr = &buf

		err := cmd.Run()
		if err != nil {
			log.Error("cmd error:%d %s=>%s do %s %s", result.FilterID, domain, ip, err.Error(), buf.String())
		} else {
			cache.Set(ip, true, time.Minute*14)
			log.Info("cmd:%d %s=>%s", result.FilterID, domain, ip)
		}
	}
}
