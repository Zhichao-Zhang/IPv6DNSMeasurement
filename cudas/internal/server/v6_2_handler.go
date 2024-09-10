package server

import (
	"Dual_Stack_DNS_Discovery/cudas/internal/utils"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func handler_v6_2(w dns.ResponseWriter, m *dns.Msg) {
	/*
		整体的逻辑：
			当qname子域名的对应位置为：v6-2时，进入该handler；
			对于AAAA记录，也就是client直接query的类型，直接返回编码后的CNAME记录，此时子域名 更换为v4-3
			具体的：
				接收到AAAA记录查询：N.IP2.IP1.v6-2.chain.dual_stack_discovery.cn
				回复CNAME：N.IP3.IP2.IP1.v4-3.chain.dual_stack_discovery.cn）

			也可能查找N.IP2.IP1.v6-2.chain.dual_stack_discovery.cn的NS记录（这是上一级v4-1返回的CNAME）
	*/
	parts := strings.Split(dns.Fqdn(m.Question[0].Name), ".")

	if len(parts) != 8 {
		logger.Debugf("invalid question name: %s %s", m.Question[0].Name, len(parts))
		emptyHandler(w, m)
		return
	}

	switch m.Question[0].Qtype {
	case dns.TypeNS:
		/*
			当问这个域名的NS，就回复另一个子域名，附上AAAA资源记录，该子域名只支持v6
		*/
		nsName := "ns-v6-2." + MainDomain
		nsOfCnameHandler(w, m, nsName)

	case dns.TypeAAAA:
		/*
			问题区：A N.IP2.IP1.v6-2.chain.dual_stack_discovery.cn
			应答区：CNAME N.IP3.IP2.IP1.v4-3.chain.dual_stack_discovery.cn
			附加趋：NS + AAAA
		*/
		ip1 := parts[len(parts)-MainDomainPartAmount-3]
		ip2 := parts[len(parts)-MainDomainPartAmount-4]

		//remoteClient := strings.Split(w.RemoteAddr().String(), ":")
		remoteClient := w.RemoteAddr().String()
		clientIP, ip3, err := utils.IpToSubdomain(remoteClient) // ip2是可以用于子域的格式，
		if err != nil {
			logger.Errorf(err.Error())
		}

		if !utils.IsIPv6(clientIP) { //如果是v4，不支持
			emptyHandler(w, m)
			return
		}

		N := utils.GetNonce()

		logger.Infof("收到请求：AAAA - qname：%s - 解析器IP： %s", m.Question[0].Name, w.RemoteAddr().String())
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess
		cname := strings.Join([]string{N, ip3, ip2, ip1, "v4-3"}, ".") + "." + MainDomain
		//logger.Infof("cname %s", cname)
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

func handler_ns_v6_2(w dns.ResponseWriter, m *dns.Msg) {
	/*
		整体的逻辑：
			当qname子域名的对应位置为：ns-v6-2时，进入该handler；只要说这种情况，支持AAAA
			只返回AAAA记录。对于AAAA记录，也就是client直接query的类型
			具体的：
				接收到AAAA记录查询：ns.chain.dual_stack_discovery.cn
	*/
	switch m.Question[0].Qtype {
	case dns.TypeAAAA:
		/*
			当问这个域名的NS，就回复另一个子域名，附上AAAA资源记录，该子域名只支持v6
		*/
		logger.Infof("收到请求：AAAA - qname：%s - 解析器IP： %s", m.Question[0].Name, w.RemoteAddr().String())
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess
		nsAddr := AuthName2Addr["ns-v6-2"]
		rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", m.Question[0].Name, nsAddr))
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
