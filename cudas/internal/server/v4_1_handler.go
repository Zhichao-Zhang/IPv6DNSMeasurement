package server

import (
	"Dual_Stack_DNS_Discovery/cudas/internal/utils"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func handler_v4_1(w dns.ResponseWriter, m *dns.Msg) {
	/*
		整体的逻辑：
			当qname子域名的对应位置为：v4-1时，进入该handler；
			对于AAAA记录，也就是client直接query的类型，直接返回编码后的CNAME记录，此时子域名 更换为v6-2
			具体的：
				接收到AAAA记录查询：N.IP1.v4-1.chain.dual_stack_discovery.cn
				回复CNAME：N.IP2.IP1.v6-2.xxx（chain.dual_stack_discovery.cn）
	*/
	switch m.Question[0].Qtype {
	case dns.TypeAAAA:
		/*
			问题区：AAAA N.IP1.v4-1.chain.dual_stack_discovery.cn
			应答区：CNAME N.IP2.IP1.v6-2.xxx（chain.dual_stack_discovery.cn）
			附加趋：NS + AAAA
		*/
		logger.Infof("收到请求：AAAA - qname：%s - 解析器IP： %s", m.Question[0].Name, w.RemoteAddr().String())
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess

		// 制定具体的CNAME，并返回结果：计算IP1，IP2
		parts := strings.Split(dns.Fqdn(m.Question[0].Name), ".")
		if len(parts) != 7 {
			logger.Debugf("invalid question name: %s %d", m.Question[0].Name, len(parts))
			emptyHandler(w, m)
			return
		}
		ip1 := parts[len(parts)-MainDomainPartAmount-2]
		remoteClient := w.RemoteAddr().String()
		clientIP, ip2, err := utils.IpToSubdomain(remoteClient) // ip2是可以用于子域的格式，
		if err != nil {
			logger.Errorf(err.Error())
		}

		if utils.IsIPv6(clientIP) { //如果是v6，不支持
			emptyHandler(w, m)
			return
		}

		N := utils.GetNonce()

		cname := strings.Join([]string{N, ip2, ip1, "v6-2"}, ".") + "." + MainDomain
		//logger.Infof("cname %s", cname)
		// 可以优化为map
		//nsName := "ns-v6-2." + MainDomain
		//auth1Addr := "240b:4001:112:7b00:79e3:688a:710c:6858"
		//
		rrCNAME, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", m.Question[0].Name, cname))
		if err != nil {
			logger.Errorf("error in build rr %s: %v", m.Question[0].Name, err)
			return
		}
		resp.Answer = append(resp.Answer, rrCNAME)
		err = w.WriteMsg(resp)
		if err != nil {
			logger.Errorf("error in writing msg: %v", err)
		}

	case dns.TypeNS:
		nxHandler(w, m)
	}
}
