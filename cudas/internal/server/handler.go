package server

import (
	"Dual_Stack_DNS_Discovery/cudas/internal/utils"
	"fmt"
	"github.com/miekg/dns"
)

func nsOfCnameHandler(w dns.ResponseWriter, m *dns.Msg, nsSubdomain string) {
	/*
		对于ns共同的部分，统一处理
		该部分是cname的ns记录的处理
	*/
	nsName := nsSubdomain + "." + MainDomain

	logger.Infof("收到请求：NS - qname：%s - 解析器IP： %s", m.Question[0].Name, w.RemoteAddr().String())
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	rr, err := dns.NewRR(fmt.Sprintf("%s NS %s", m.Question[0].Name, nsName))
	if err != nil {
		logger.Errorf("error in build rr %s: %v", m.Question[0].Name, err)
		return
	}
	resp.Ns = append(resp.Ns, rr)

	nsAddr := AuthName2Addr[nsSubdomain]
	logger.Infof("nsName %s, nsAddr : %s", nsSubdomain, nsAddr)
	// 根据地址类型不同，给不同的资源记录
	if utils.IsIPv6(nsAddr) {
		rrExtra, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", nsName, nsAddr))
		if err != nil {
			logger.Errorf("error in build rr %s %s: %v ", nsAddr, m.Question[0].Name, err)
			return
		}
		resp.Extra = append(resp.Extra, rrExtra)
	} else {
		rrExtra, err := dns.NewRR(fmt.Sprintf("%s A %s", nsName, nsAddr))
		if err != nil {
			logger.Errorf("error in build rr %s %s %v", m.Question[0].Name, nsAddr, err)
			return
		}
		resp.Extra = append(resp.Extra, rrExtra)
	}

	err = w.WriteMsg(resp)
	if err != nil {
		logger.Errorf("error in writing msg: %v", err)
	}
}

func defaultHandler(w dns.ResponseWriter, m *dns.Msg) {
	switch m.Question[0].Qtype {
	case dns.TypeA:
		nxHandler(w, m)
	case dns.TypeNS:
		//nsHandler(w, m, NSv4)
		nxHandler(w, m)
	}
}

func refuseHandler(w dns.ResponseWriter, m *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Rcode = dns.RcodeRefused
	_ = w.WriteMsg(resp)
	return
}

func nxHandler(w dns.ResponseWriter, m *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeNameError
	_ = w.WriteMsg(resp)
	return
}

func emptyHandler(w dns.ResponseWriter, m *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	_ = w.WriteMsg(resp)
	return
}
func aaaaHandler(w dns.ResponseWriter, m *dns.Msg, addr_v6 string) {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", m.Question[0].Name, addr_v6))
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

func aHandler(w dns.ResponseWriter, m *dns.Msg, addr_v4 string) {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	rr, err := dns.NewRR(fmt.Sprintf("%s A %s", m.Question[0].Name, addr_v4))
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

func nsHandler(w dns.ResponseWriter, m *dns.Msg, ns string) {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	rr, err := dns.NewRR(fmt.Sprintf("%s NS %s", m.Question[0].Name, ns))
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

func cnameHandler(w dns.ResponseWriter, m *dns.Msg, cname string) {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	rr, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", m.Question[0].Name, cname))
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

func alidnsHandler(w dns.ResponseWriter, m *dns.Msg) {
	switch m.Question[0].Qtype {
	case dns.TypeTXT:
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Authoritative = true
		rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", m.Question[0].Name, "b5c771fafa334314a5a49f8c710ff619"))
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

func test8Handler(w dns.ResponseWriter, m *dns.Msg) {
	switch m.Question[0].Qtype {
	case dns.TypeNS:
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Authoritative = true
		rr, err := dns.NewRR(fmt.Sprintf("%s NS %s", m.Question[0].Name, "ns1.alidns.com"))
		if err != nil {
			logger.Errorf("error in build rr %s: %v", m.Question[0].Name, err)
			return
		}
		resp.Answer = append(resp.Answer, rr)
		rr, err = dns.NewRR(fmt.Sprintf("%s NS %s", m.Question[0].Name, "ns2.alidns.com"))
		if err != nil {
			logger.Errorf("error in build rr %s: %v", m.Question[0].Name, err)
			return
		}
		resp.Answer = append(resp.Answer, rr)
		err = w.WriteMsg(resp)
		if err != nil {
			logger.Errorf("error in writing msg: %v", err)
		}
		return

	}
}
