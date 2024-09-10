package server

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func handler_v6_4(w dns.ResponseWriter, m *dns.Msg) {
	/*
		整体的逻辑：
			当qname子域名的对应位置为：v6-4时，进入该handler；
			对于AAAA记录，也就是client直接query的类型，直接返回编码后的CNAME记录，此时子域名 更换为v4-3
			具体的：
				接收到AAAA记录查询：N.IP4.IP3.IP2.IP1.v6-2.chain.dual_stack_discovery.cn
				回复IPv6地址

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
		nsName := "ns-v6-4." + MainDomain
		nsOfCnameHandler(w, m, nsName)

	case dns.TypeAAAA:
		/*
			问题区：AAAA N.IP2.IP1.v6-2.chain.dual_stack_discovery.cn
			应答区：结果
		*/

		//remoteClient := strings.Split(w.RemoteAddr().String(), ":")

		logger.Infof("收到请求：AAAA - qname：%s - 解析器IP： %s", m.Question[0].Name, w.RemoteAddr().String())
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess
		rrAAAA, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", m.Question[0].Name, "2001::"))
		if err != nil {
			logger.Errorf("error in build rr %s: %v", m.Question[0].Name, err)
			return
		}
		resp.Answer = append(resp.Answer, rrAAAA)
		err = w.WriteMsg(resp)
		if err != nil {
			logger.Errorf("error in writing msg: %v", err)
		}

	}
}

func handler_ns_v6_4(w dns.ResponseWriter, m *dns.Msg) {
	/*
		整体的逻辑：
			当qname子域名的对应位置为：ns-v6-4时，进入该handler；只要说这种情况，支持AAAA
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
		nsAddr := AuthName2Addr["ns-v6-4"]
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
