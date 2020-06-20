package worker

import (
	"os/exec"
	"strings"

	"github.com/AdguardTeam/AdGuardHome/dnsfilter"
	"github.com/AdguardTeam/AdGuardHome/querylog"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

var (
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
func ProcessDNSResult(params querylog.AddParams) {
	result := params.Result

	if result.IsFiltered || result.Reason != dnsfilter.NotFilteredWhiteList {
		return
	}

	if result.FilterID < 10 {
		return
	}

	var domain, ip string
	for _, answer := range params.Answer.Answer {
		domain = strings.ToLower(answer.Header().Name)
		domain = domain[:len(domain)-1] // remove last "."

		switch answer.Header().Rrtype {
		case dns.TypeA:
			ip = answer.(*dns.A).A.String()
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
