package utils

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

func IpToInt36(ip net.IP) string {
	s := strconv.FormatInt(int64(binary.BigEndian.Uint32(ip.To4()[0:4])), 36)
	for len(s) < 6 {
		s = "0" + s
	}
	return s
}

func Int36ToIp(s string) net.IP {
	n, _ := strconv.ParseInt(s, 36, 32)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(n))
	return ip
}

func Hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
}

func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".") && ip.To4() != nil
}

func GetNonce() string {
	rand.Seed(time.Now().UnixNano()) // 设置随机种子˛
	randomNumber := rand.Intn(1000000)
	// 将整数转换为字符串
	return strconv.Itoa(randomNumber)
}

func IpToSubdomain(remoteClient string) (string, string, error) {
	// 给一个DNS答复的IP，判断是v4还是v6，最后处理为可以放到子域名的字符串
	var clientIP string
	var ip_subdomain string
	if strings.Contains(remoteClient, "]:") { // 判断是ipv6，还是ipv4
		remoteClient := strings.Split(remoteClient, "]:")
		clientIP = remoteClient[0][1:]
	} else {
		remoteClient := strings.Split(remoteClient, ":")
		clientIP = remoteClient[0]
	}

	if net.ParseIP(clientIP) == nil {
		return "", "", fmt.Errorf("error: not an client IP addr %s", remoteClient)
	}

	if IsIPv6(clientIP) {
		ip_subdomain = strings.Replace(clientIP, ":", "x", -1)
	} else {
		ip_subdomain = strings.Replace(clientIP, ".", "y", -1)
	}
	return clientIP, ip_subdomain, nil

}
