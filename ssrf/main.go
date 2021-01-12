package main

import (
	"fmt"
	"net"
	"net/url"
)

// IsLocalIP 判断是否是内网ip
func IsLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// 判断是否是回环地址, ipv4时是127.0.0.1；ipv6时是::1
	if ip.IsLoopback() {
		return true
	}
	ip4 := ip.To4()
	return ip4[0] == 10 || // 10.0.0.0/8
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || // 172.16.0.0/12
		(ip4[0] == 192 && ip4[1] == 168) // 192.168.0.0/16
}

func main() {
	checkList := []string{
		"http://0266.075.0310.07/",
		"http://www.192.168.3.6.xip.io",
		"http://www.baidu.com@192.168.1.3",
		"http://0xc0.0xa8.774",
		"http://182.4048903",
	}
	for _, reqURL := range checkList {
		uri, err := url.Parse(reqURL)
		if err != nil {
			fmt.Println(err)
			continue
		}
		ips, err := net.LookupIP(uri.Hostname())
		if err != nil {
			fmt.Println(err)
			continue
		}
		for _, ip := range ips {
			fmt.Printf("%s -> %s is localip?: %v\n", uri.Hostname(), ip.String(), IsLocalIP(ip))
		}
	}
}
