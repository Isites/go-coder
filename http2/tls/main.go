package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	// server write and client read
	s2c = new(bytes.Buffer)
	// client wirte and server read
	c2s     = new(bytes.Buffer)
	s2cCond = sync.NewCond(new(sync.Mutex))
	c2sCond = sync.NewCond(new(sync.Mutex))
)

// 简单实现net.Addr接口
type tcpAddr string

func (addr tcpAddr) Network() string {
	return "tcp"
}

func (addr tcpAddr) String() string {
	return string(addr)
}

// 简单模拟实现底层连接
type tcpCon struct {
	local    tcpAddr
	remote   tcpAddr
	isClient bool
}

func (c *tcpCon) Read(b []byte) (n int, err error) {
	if c.isClient {
		if s2c.Len() == 0 {
			s2cCond.L.Lock()
			defer s2cCond.L.Unlock()
			s2cCond.Wait()
		}
		return s2c.Read(b)
	}
	if c2s.Len() == 0 {
		c2sCond.L.Lock()
		defer c2sCond.L.Unlock()
		c2sCond.Wait()
	}
	return c2s.Read(b)
}
func (c *tcpCon) Write(b []byte) (n int, err error) {
	if c.isClient {
		n, err = c2s.Write(b)
		c2sCond.Signal()
		return n, err
	}
	n, err = s2c.Write(b)
	s2cCond.Signal()
	return n, err
}
func (c *tcpCon) Close() error {
	return nil
}
func (c *tcpCon) LocalAddr() net.Addr {
	return c.local
}
func (c *tcpCon) RemoteAddr() net.Addr {
	return c.remote
}
func (c *tcpCon) SetDeadline(t time.Time) error {
	return nil
}
func (c *tcpCon) SetReadDeadline(t time.Time) error {
	return nil
}
func (c *tcpCon) SetWriteDeadline(t time.Time) error {
	return nil
}
func (c *tcpCon) tttt() error {
	fmt.Println(c)
	return nil
}

// 参考 http2configureTransport
func clientTLSConf() *tls.Config {
	tlsConf := new(tls.Config)
	tlsConf.NextProtos = append(tlsConf.NextProtos, "h2", "http/1.1")
	return tlsConf
}

// 参考 (srv *Server) ServeTLS( http2ConfigureServer
func serverTLSConf(certFile, keyFile string) (*tls.Config, error) {
	tlsConf := new(tls.Config)
	// Note: not setting MinVersion to tls.VersionTLS12,
	// as we don't want to interfere with HTTP/1.1 traffic
	// on the user's server. We enforce TLS 1.2 later once
	// we accept a connection. Ideally this should be done
	// during next-proto selection, but using TLS <1.2 with
	// HTTP/2 is still the client's bug.
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
	return tlsConf, nil
}

func main() {
	var wg sync.WaitGroup
	sc := &tcpCon{
		local:  "127.0.0.1",
		remote: "172.18.16.51",
	}
	cs := &tcpCon{
		local:    "127.0.0.1",
		remote:   "172.18.16.51",
		isClient: true,
	}
	sconf, err := serverTLSConf("ca.crt", "ca.key")
	if err != nil {
		fmt.Println("init server tls conf", err)
		return
	}
	cconf := clientTLSConf()
	// 允许不安全证书验证
	cconf.InsecureSkipVerify = true
	server := tls.Server(sc, sconf)
	client := tls.Client(cs, cconf)
	wg.Add(2)
	// client
	go func() {
		if err := client.Handshake(); err != nil {
			fmt.Println("client handshake", err)
			wg.Done()
			return
		}
		fmt.Println(client.ConnectionState())
		wg.Done()
	}()
	// server
	go func() {
		if err := server.Handshake(); err != nil {
			fmt.Println("server handshake", err)
			wg.Done()
			return
		}
		fmt.Println(server.ConnectionState())
		wg.Done()
	}()
	wg.Wait()
}
