package server

import (
	"Dual_Stack_DNS_Discovery/cudas/internal/utils"
	"bufio"
	"fmt"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/miekg/dns"
	"io"
	"log"
	"os"
	"strings"
	. "time"
)

func producer(filepath string, input chan<- *dnsQueryMeta) {
	file, err := os.Open(filepath)
	if err != nil {
		logger.Errorf("fail to open file : %s", err.Error())
		return
	}
	defer file.Close()
	fileReader := bufio.NewReader(file)
	for i := 0; i < 10000000; i++ {
		line, err := fileReader.ReadString('\n')
		if err == io.EOF {
			return
		}
		if err != nil {
			logger.Errorf("fileReader error %s", err)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.Split(line, "|")
		if len(parts) < 1 {
			logger.Warnf("读取dns时的ip地址无法分割 %s", line)
			continue
		}
		dnsAddr := parts[0]
		log.Printf("************NEXT ADDR ***************: %s  %d \n", dnsAddr, i)
		var prefixIp string
		if utils.IsIPv4(dnsAddr) {
			prefixIp = strings.Replace(dnsAddr, ".", "y", 4)
		} else if utils.IsIPv6(dnsAddr) {
			prefixIp = strings.Replace(dnsAddr, ":", "x", -1)
		} else {
			continue
		}
		N := utils.GetNonce()
		domainName := strings.Join([]string{N, prefixIp, "v4-1"}, ".") + "." + MainDomain

		m1 := new(dns.Msg)
		m1.Id = dns.Id()
		m1.RecursionDesired = true
		m1.Question = make([]dns.Question, 1)
		m1.Question[0] = dns.Question{dns.Fqdn(domainName), dns.TypeAAAA, dns.ClassINET}
		input <- &dnsQueryMeta{
			Msg:  m1,
			Addr: dnsAddr,
		}
		sleepTime := 200
		duration := gconv.Duration(sleepTime * 1000000)
		timer := NewTimer(duration)
		<-timer.C
	}
}

func dnsWorker(metaCh <-chan *dnsQueryMeta, finishCh chan<- bool) {
	c := &dns.Client{Timeout: Second * 5}
	for meta := range metaCh {
		retryCount := 0
	retry:
		in, _, err := c.Exchange(meta.Msg, meta.Addr+":53")
		if err != nil {
			//logger.Errorf("client发送出错 %s", err)
			fmt.Printf("Connection timeout : IP %s ; Domain %s \n", meta.Addr, meta.Msg.Question[0].String())
			if retryCount >= 1 {
				continue
			}
			retryCount += 1
			goto retry
		} else {
			logger.Infof("dns response %s \n", in)
		}
	}
	finishCh <- true
}
