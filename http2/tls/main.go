package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"sync"

	"github.com/Isites/go-coder/http2/tls/handsh"
)

// 参考 http2configureTransport
func clientTLSConf(certFile, keyFile string) (*tls.Config, error) {
	tlsConf := new(tls.Config)
	tlsConf.NextProtos = append(tlsConf.NextProtos, "h2", "http/1.1")
	tlsConf.Certificates = make([]tls.Certificate, 1)
	if len(certFile) > 0 && len(keyFile) > 0 {
		var err error
		tlsConf.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
	}
	// tlsConf.KeyLogWriter = handsh.KeyLog("client")
	return tlsConf, nil
}

// 参考 (srv *Server) ServeTLS( http2ConfigureServer
func serverTLSConf(certFile, keyFile string) (*tls.Config, error) {
	tlsConf := new(tls.Config)
	tlsConf.PreferServerCipherSuites = true
	// support http2
	tlsConf.NextProtos = append(tlsConf.NextProtos, "h2", "http/1.1")
	// 准备证书
	tlsConf.Certificates = make([]tls.Certificate, 1)
	var err error
	tlsConf.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	// tlsConf.KeyLogWriter = handsh.KeyLog("server")
	return tlsConf, nil
}

func main() {
	var wg sync.WaitGroup
	// server write and client read
	var s2c = new(bytes.Buffer)
	// client wirte and server read
	var c2s = new(bytes.Buffer)
	// server和client交替写，即每次只有一个人写，读也是同理
	var ch = make(chan int, 1)
	sconf, err := serverTLSConf("server.crt", "server.key")
	// sconf.ClientAuth = tls.RequireAndVerifyClientCert
	if err != nil {
		fmt.Println("init server tls conf", err)
		return
	}
	cconf, err := clientTLSConf("client.crt", "client.key")
	if err != nil {
		fmt.Println("init client tls conf", err)
		return
	}
	// 允许不安全证书验证
	cconf.InsecureSkipVerify = true
	cconf.Rand = &handsh.Rand{}
	sconf.Rand = &handsh.Rand{}
	praser := handsh.NewParser(cconf)
	sc := &handsh.TCPCon{
		Local:  "127.0.0.1",
		Remote: "172.18.16.51",
		Wbuf:   s2c,
		Rbuf:   c2s,
		Wdone:  ch,
		Rdone:  ch,
		Praser: praser,
	}
	cs := &handsh.TCPCon{
		Local:    "127.0.0.1",
		Remote:   "172.18.16.51",
		Wbuf:     c2s,
		Rbuf:     s2c,
		Wdone:    ch,
		Rdone:    ch,
		IsClient: true,
		Praser:   praser,
	}
	// 可以限制tls1.2，tls1.3和tls1.2流程不一样
	// sconf.MaxVersion = tls.VersionTLS12
	server := tls.Server(sc, sconf)
	client := tls.Client(cs, cconf)
	wg.Add(2)
	// client
	go func() {
		if err := client.Handshake(); err != nil {
			fmt.Println("client handshake err", err)
			wg.Done()
			return
		}
		// fmt.Printf("client: %+v\n", client.ConnectionState())
		wg.Done()
	}()
	// server
	go func() {
		if err := server.Handshake(); err != nil {
			fmt.Println("server handshake err", err)
			wg.Done()
			return
		}
		// fmt.Printf("server: %+v\n", server.ConnectionState())
		wg.Done()
	}()
	wg.Wait()
	client.Write([]byte("点赞关注：新世界杂货铺"))
	close(ch)
	praser.LastCheck()
}
