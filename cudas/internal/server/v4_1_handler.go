package server

import (
	"Dual_Stack_DNS_Discovery/cudas/internal/utils"
	"github.com/miekg/dns"
	"strings"
)

func handler_v4_1(w dns.ResponseWriter, m *dns.Msg) {
	/*
		整体的逻辑：
			当qname子域名的对应位置为：v4-1时，进入该handler；
			该子域名，只有NS记录，配置为N.IP2.IP1.v6-2.xxx（chain.dual_stack_discovery.cn）

			对于NS记录，也就是client直接query的类型，直接返回编码后的CNAME记录，此时子域名 更换为v6-2
			具体的：
				接收到NS记录查询：N.IP1.v4-1.chain.dual_stack_discovery.cn
				回复NS：N.IP2.IP1.v6-2.xxx（chain.dual_stack_discovery.cn）
	*/
	switch m.Question[0].Qtype {
	case dns.TypeAAAA:
		/*
			问题区：NS N.IP1.v4-1.dual_stack_discovery.cn
			应答区：CNAME N.IP2.IP1.v6-2.xxx（dual_stack_discovery.cn）
			附加趋：NS + AAAA
		*/
		print("11")
		logger.Infof("收到请求：AAAA - qname：%s - 解析器IP： %s", m.Question[0].Name, w.RemoteAddr().String())

		// 制定具体的CNAME，并返回结果：计算IP1，IP2
		parts := strings.Split(dns.Fqdn(m.Question[0].Name), ".")
		if len(parts) != 6 {
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

		cName := strings.Join([]string{N, ip2, ip1, "v6-2"}, ".") + "." + MainDomain_auth2
		logger.Infof("响应：AAAA - qname：%s - 解析器IP： %s - CNAME记录 %s", m.Question[0].Name, w.RemoteAddr().String(), cName)
		cnameHandler(w, m, cName)

	case dns.TypeNS:
		nsHandler(w, m, "ns1.dual-stack-ns.top")
	}
}
