package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	xtls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func main() {
	// http 1.1的实验
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{}
		con, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// 根据地址获取host信息
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// 并且不验证host信息
		xtlsConf := &xtls.Config{
			ServerName:    host,
			Renegotiation: xtls.RenegotiateNever,
		}
		// 构建tls.UConn
		xtlsConn := xtls.UClient(con, xtlsConf, xtls.HelloCustom)
		clientHelloSpec := &xtls.ClientHelloSpec{
			TLSVersMax: tls.VersionTLS12,
			TLSVersMin: tls.VersionTLS10,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				2333,
			},
			CompressionMethods: []byte{
				0,
			},
			Extensions: []xtls.TLSExtension{
				&xtls.RenegotiationInfoExtension{Renegotiation: xtls.RenegotiateOnceAsClient},
				&xtls.SNIExtension{ServerName: host},
				&xtls.UtlsExtendedMasterSecretExtension{},
				&xtls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []xtls.SignatureScheme{
					xtls.ECDSAWithP256AndSHA256,
					xtls.PSSWithSHA256,
					xtls.PKCS1WithSHA256,
					xtls.ECDSAWithP384AndSHA384,
					xtls.ECDSAWithSHA1,
					xtls.PSSWithSHA384,
					xtls.PSSWithSHA384,
					xtls.PKCS1WithSHA384,
					xtls.PSSWithSHA512,
					xtls.PKCS1WithSHA512,
					xtls.PKCS1WithSHA1}},
				&xtls.StatusRequestExtension{},
				&xtls.NPNExtension{},
				&xtls.SCTExtension{},
				&xtls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&xtls.SupportedPointsExtension{SupportedPoints: []byte{1}}, // uncompressed
				&xtls.SupportedCurvesExtension{
					Curves: []xtls.CurveID{
						xtls.X25519,
						xtls.CurveP256,
						xtls.CurveP384,
						xtls.CurveP521,
					},
				},
			},
		}
		// 定义hellomsg的加密套件等信息
		err = xtlsConn.ApplyPreset(clientHelloSpec)
		if err != nil {
			return nil, err
		}
		// 握手
		err = xtlsConn.Handshake()
		if err != nil {
			return nil, err
		}
		fmt.Println("当前请求使用协议：", xtlsConn.HandshakeState.ServerHello.AlpnProtocol)
		return xtlsConn, err
	}
	c := http.Client{
		Transport: tr,
	}
	resp, err := c.Get("https://ja3er.com/json")
	if err != nil {
		fmt.Println(err)
		return
	}
	bts, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Println(string(bts), err)

	// 判断是否支持http2
	// resp, err = c.Get("https://dss0.bdstatic.com/5aV1bjqh_Q23odCf/static/superman/img/topnav/newzhidao-da1cf444b0.png")
	// if err != nil {
	// 	fmt.Println("req http2 err:", err)
	// 	return
	// }
	// io.CopyN(io.Discard, resp.Body, 2<<10)
	// resp.Body.Close()
	// fmt.Println(resp.StatusCode)

	// http 2的实验
	con, err := tr.DialTLSContext(context.Background(), "tcp", "dss0.bdstatic.com:443")
	if err != nil {
		fmt.Println("DialTLSContext", err)
		return
	}
	tr2 := http2.Transport{}
	h2Con, err := tr2.NewClientConn(con)
	if err != nil {
		fmt.Println("NewClientConn", err)
		return
	}
	req, _ := http.NewRequest("GET", "https://dss0.bdstatic.com/5aV1bjqh_Q23odCf/static/superman/img/topnav/newzhidao-da1cf444b0.png", nil)
	resp2, err := h2Con.RoundTrip(req)
	if err != nil {
		fmt.Println("RoundTrip", err)
		return
	}
	io.CopyN(io.Discard, resp2.Body, 2<<10)
	resp2.Body.Close()
	fmt.Println("响应code: ", resp2.StatusCode)

}
