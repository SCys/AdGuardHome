package worker

import (
	"os/exec"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/dnsfilter"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

const (
	queueSize       = 1000            // size chan
	elapsedMaxLimit = 1 * time.Second // ignored over
)

var (
	// cache        = ccache.New(ccache.Configure().MaxSize(1000).ItemsToPrune(100))
	manager      = RuleManager{}
	queueDefault chan string
)

func _nftCmd(ip string) error {
	cmd := exec.Command("nft", "add", "element", "gfw", "temp", "{", ip, "timeout", "24h", "}")

	// var buf bytes.Buffer
	// cmd.Stderr = &buf

	return cmd.Run()
}

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

			// if item := cache.Get(ip); item != nil {
			// 	log.Debug("ignore:%s=>%s", domain, ip)
			// 	continue
			// }

			// TODO support AAA
			// case dns.TypeAAAA:
			// ip = answer.(*dns.AAAA).AAAA.String()
		}

		if ip == "" {
			continue
		}

		if err := _nftCmd(ip); err != nil {
			log.Error("cmd error:%d %s=>%s do %s", result.FilterID, domain, ip, err.Error())
		} else {
			// cache.Set(ip, true, 30*time.Second)
			log.Info("cmd:%d %s=>%s", result.FilterID, domain, ip)
		}
	}
}
