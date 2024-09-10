package server

import (
	"Dual_Stack_DNS_Discovery/cudas/internal/utils"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func handler_v4_3(w dns.ResponseWriter, m *dns.Msg) {
	/*
		整体的逻辑：
			当qname子域名的对应位置为：v4-3时，进入该handler；
			对于AAAA记录，也就是client直接query的类型，直接返回编码后的CNAME记录，此时子域名 更换为v6-4
			具体的：
				接收到AAAA记录查询：N.IP3.IP2.IP1.v4-3.chain.dual_stack_discovery.cn
				回复CNAME：N.IP4.IP3.IP2.IP1.v6-4.chain.dual_stack_discovery.cn
			其次：
				也可能查找N.IP3.IP2.IP1.v4-3.chain.dual_stack_discovery.cn的NS记录（这是上一级v6-2返回的CNAME）
	*/
	parts := strings.Split(dns.Fqdn(m.Question[0].Name), ".")

	if len(parts) != 9 {
		logger.Debugf("invalid question name: %s %s", m.Question[0].Name, len(parts))
		emptyHandler(w, m)
		return
	}

	switch m.Question[0].Qtype {
	case dns.TypeNS:
		/*
			当问这个域名的NS，就回复另一个子域名，附上AAAA资源记录，该子域名只支持v6
		*/
		nsName := "ns-v4-3." + MainDomain
		nsOfCnameHandler(w, m, nsName)

	case dns.TypeAAAA:
		/*
			问题区：AAAA N.IP3.IP2.IP1.v4-3.chain.dual_stack_discovery.cn
			应答区：CNAME N.IP4.IP3.IP2.IP1.v6-4.chain.dual_stack_discovery.cn
		*/
		ip1 := parts[len(parts)-MainDomainPartAmount-3]
		ip2 := parts[len(parts)-MainDomainPartAmount-4]
		ip3 := parts[len(parts)-MainDomainPartAmount-5]

		//remoteClient := strings.Split(w.RemoteAddr().String(), ":")
		remoteClient := w.RemoteAddr().String()
		clientIP, ip4, err := utils.IpToSubdomain(remoteClient) // ip2是可以用于子域的格式，
		if err != nil {
			logger.Errorf(err.Error())
		}

		if utils.IsIPv6(clientIP) { //如果是v6，不支持
			emptyHandler(w, m)
			return
		}

		N := utils.GetNonce()

		logger.Infof("收到请求：AAAA - qname：%s - 解析器IP： %s", m.Question[0].Name, w.RemoteAddr().String())
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess
		cname := strings.Join([]string{N, ip4, ip3, ip2, ip1, "v6-4"}, ".") + "." + MainDomain
		logger.Infof("cname %s", cname)
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

	}
}

func handler_ns_v4_3(w dns.ResponseWriter, m *dns.Msg) {
	/*
		整体的逻辑：
			当qname子域名的对应位置为：ns-v6-2时，进入该handler；只要说这种情况，支持AAAA
			只返回AAAA记录。对于AAAA记录，也就是client直接query的类型
			具体的：
				接收到AAAA记录查询：ns.chain.dual_stack_discovery.cn
	*/
	switch m.Question[0].Qtype {
	case dns.TypeA:
		/*
			当问这个域名的NS，就回复另一个子域名，附上A资源记录，该子域名只支持v4
		*/
		logger.Infof("收到请求：A - qname：%s - 解析器IP： %s", m.Question[0].Name, w.RemoteAddr().String())
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess
		nsAddr := AuthName2Addr["ns-v4-3"]
		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", m.Question[0].Name, nsAddr))
		if err != nil {
			logger.Errorf("error in build rr %s: %v", m.Question[0].Name, err)
			return
		}
		resp.Answer = append(resp.Answer, rr)

		err = w.WriteMsg(resp)
		if err != nil {
			logger.Errorf("error in writing msg: %v", err)
		}

	}
}
