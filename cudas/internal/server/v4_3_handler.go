package server

import (
	"Dual_Stack_DNS_Discovery/cudas/internal/utils"
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

	switch m.Question[0].Qtype {
	/*
		case dns.TypeNS:

				//当问这个域名的NS，就回复另一个子域名，附上AAAA资源记录，该子域名只支持v6

			nsName := "ns-v4-3" + MainDomain
			nsOfCnameHandler(w, m, nsName)

	*/

	case dns.TypeAAAA:
		/*
			问题区：AAAA N.IP3.IP2.IP1.v4-3.dual_stack_discovery.cn
			应答区：CNAME N.IP4.IP3.IP2.IP1.v6-4.dual_stack_discovery.cn
		*/
		parts := strings.Split(dns.Fqdn(m.Question[0].Name), ".")

		if len(parts) != 8 {
			logger.Debugf("invalid question name: %s %s", m.Question[0].Name, len(parts))
			emptyHandler(w, m)
			return
		}

		ip1 := parts[len(parts)-MainDomainPartAmount-2]
		ip2 := parts[len(parts)-MainDomainPartAmount-3]
		ip3 := parts[len(parts)-MainDomainPartAmount-4]

		//remoteClient := strings.Split(w.RemoteAddr().String(), ":")
		remoteClient := w.RemoteAddr().String()
		clientIP, ip4, err := utils.IpToSubdomain(remoteClient) // ip2是可以用于子域的格式，
		if err != nil {
			logger.Errorf(err.Error())
		}

		if utils.IsIPv6(clientIP) { //如果是v6，不支持
			//emptyHandler(w, m)
			//return
			logger.Debugf("client ip is ipv6: %s %s", m.Question[0].Name, m.Question[0].Qtype)

		}

		N := utils.GetNonce()

		cname := strings.Join([]string{N, ip4, ip3, ip2, ip1, "v6-4"}, ".") + "." + MainDomain_auth4
		logger.Infof("收到请求：AAAA - qname：%s - 解析器IP： %s - 回复cname: %s", m.Question[0].Name, w.RemoteAddr().String(), cname)

		cnameHandler(w, m, cname)

	}
}
