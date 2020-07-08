package worker

import (
	"os/exec"
	"strings"

	"github.com/AdguardTeam/AdGuardHome/dnsfilter"
	"github.com/AdguardTeam/AdGuardHome/querylog"
	"github.com/AdguardTeam/golibs/log"
	"github.com/lionsoul2014/ip2region/binding/golang/ip2region"
	"github.com/miekg/dns"
)

var region *ip2region.Ip2Region

func _nftCmd(ip string) error {
	cmd := exec.Command("nft", "add", "element", "gfw", "temp", "{", ip, "timeout", "24h", "}")
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

		info, err := region.MemorySearch(ip)
		if err != nil {
			log.Error("ip2region error:%s", err.Error())
			continue
		}

		// ignore chinese ip
		if info.Country == "中国" || info.Country == "China" || info.Country == "CN" {
			continue
		}

		if err := _nftCmd(ip); err != nil {
			log.Error("cmd error:%d %s=>%s do %s", result.FilterID, domain, ip, err.Error())
		} else {
			// cache.Set(ip, true, 30*time.Second)
			// log.Info("cmd:%d %s=>%s", result.FilterID, domain, ip)
			log.Info("setup %s=>%s location %s/%s/%s", domain, ip, info.Country, info.Province, info.City)
		}
	}
}

func init() {
	var err error

	region, err = ip2region.New("/data/data/ip2region.db")
	if err != nil {
		log.Fatalf("ip2region error:%s", err.Error())
	}
}
