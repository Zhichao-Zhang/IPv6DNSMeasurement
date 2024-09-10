package server

import (
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"strconv"
	"strings"
	"sync"
)

var logger = initLogger(true)

//var Indexer = utils.InitBulkIndexer(Es)
var MeasLocation = "qingdao"
var wg sync.WaitGroup

var MainDomain string
var NSv4 string
var NSv6 string
var handlerMap map[string]func(dns.ResponseWriter, *dns.Msg)

var MainDomainPartAmount = 3

type dnsQueryMeta struct {
	Msg  *dns.Msg
	Addr string
}

var AuthName2ns map[string]string
var AuthName2Addr map[string]string

func handleDnsRequest(w dns.ResponseWriter, m *dns.Msg) {
	if m.Response {
		logger.Errorf("Not response!!!")
		return
	}
	if m.Opcode != dns.OpcodeQuery || len(m.Question) == 0 {
		logger.Errorf("Not Correct Opcode!!!")
		refuseHandler(w, m)
	}
	if !strings.HasSuffix(m.Question[0].Name, MainDomain) {
		logger.Errorf("Wrong Domain Suffix!!! %s", m.Question[0].Name)
		refuseHandler(w, m)
		return
	}
	parts := strings.Split(m.Question[0].Name, ".")
	if len(parts) == MainDomainPartAmount {
		//logger.Infof("MainDomain Parts Length %d", len(parts))
		switch m.Question[0].Qtype {
		case dns.TypeA:
			//cnameHandler(w, m)
			nxHandler(w, m)
		case dns.TypeNS:

			nxHandler(w, m)
			//nsHandler(w, m, NSv4)
		}
		return
	}
	handler, ok := handlerMap[parts[len(parts)-MainDomainPartAmount-1]] // 匹配子域名
	// xxx.v4-1.chain.dsd.cn
	//logger.Debugf("验证 parts %s", parts[len(parts)-MainDomainPartAmount-1])
	if !ok {
		handler = defaultHandler
	}

	handler(w, m)
}

func Main(mode string) {
	AuthName2Addr = map[string]string{
		"ns-v6-2": "240b:4001:112:7b00:79e3:688a:710c:6858",
		"ns-v6-4": "240b:4001:112:7b00:79e3:688a:710c:6454",
		"ns-v4-3": "8.210.233.140",
	}
	switch mode {
	case "cudas":
		MainDomain = dns.Fqdn("chain.dual-stack-discovery.cn.")
		handlerMap = map[string]func(dns.ResponseWriter, *dns.Msg){
			// 子域名的匹配，遇到不同子域名，给不同的处理
			"v4-1":    handler_v4_1,
			"v6-2":    handler_v6_2,
			"v4-3":    handler_v4_3,
			"v6-4":    handler_v6_4,
			"ns-v6-2": handler_ns_v6_2,
			"ns-v6-4": handler_ns_v6_4,
			"ns-v4-3": handler_ns_v4_3,
		}
		MainDomainPartAmount = len(strings.Split(MainDomain, "."))
		dns.HandleFunc(MainDomain, handleDnsRequest)
	}
	// start server
	port := 53
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
	defer server.Shutdown()

}

func initLogger(debug bool) *zap.SugaredLogger {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if debug {
		cfg.Level.SetLevel(zapcore.DebugLevel)
	} else {
		cfg.Level.SetLevel(zapcore.InfoLevel)
	}
	logger, _ := cfg.Build()
	defer logger.Sync()
	return logger.Sugar()
}
