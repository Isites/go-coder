package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
	typeNextProtocol        uint8 = 67  // Not IANA assigned
	typeMessageHash         uint8 = 254 // synthetic message
)

const (
	maxPlaintext       = 16384        // maximum plaintext payload length
	maxCiphertext      = 16384 + 2048 // maximum ciphertext payload length
	maxCiphertextTLS13 = 16384 + 256  // maximum ciphertext length in TLS 1.3
	recordHeaderLen    = 5            // record header length
	maxHandshake       = 65536        // maximum handshake we support (protocol max is 16 MB)
	maxUselessRecords  = 16           // maximum number of consecutive non-advancing records
)

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// 简单实现net.Addr接口
type tcpAddr string

type recordType uint8

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
	wbuf     *bytes.Buffer
	rbuf     *bytes.Buffer
	wdone    chan<- int
	rdone    <-chan int
}

type macFunction interface {
	// Size returns the length of the MAC.
	Size() int
	// MAC appends the MAC of (seq, header, data) to out. The extra data is fed
	// into the MAC after obtaining the result to normalize timing. The result
	// is only valid until the next invocation of MAC as the buffer is reused.
	MAC(seq, header, data, extra []byte) []byte
}

type halfConn struct {
	sync.Mutex

	err            error       // first permanent error
	version        uint16      // protocol version
	cipher         interface{} // cipher algorithm
	mac            macFunction
	seq            [8]byte  // 64-bit sequence number
	additionalData [13]byte // to avoid allocs; interface method args escape

	nextCipher interface{} // next encryption state
	nextMac    macFunction // next MAC algorithm

	trafficSecret []byte // current TLS 1.3 traffic secret
}

// func (hc *halfConn) decrypt(record []byte) ([]byte, recordType, error) {
// 	var plaintext []byte
// 	typ := recordType(record[0])
// 	payload := record[recordHeaderLen:]

// 	// In TLS 1.3, change_cipher_spec messages are to be ignored without being
// 	// decrypted. See RFC 8446, Appendix D.4.
// 	if hc.version == tls.VersionTLS13 && typ == recordTypeChangeCipherSpec {
// 		return payload, typ, nil
// 	}

// 	paddingGood := byte(255)
// 	paddingLen := 0

// 	explicitNonceLen := hc.explicitNonceLen()

// 	if hc.cipher != nil {
// 		switch c := hc.cipher.(type) {
// 		case cipher.Stream:
// 			c.XORKeyStream(payload, payload)
// 		case aead:
// 			if len(payload) < explicitNonceLen {
// 				return nil, 0, alertBadRecordMAC
// 			}
// 			nonce := payload[:explicitNonceLen]
// 			if len(nonce) == 0 {
// 				nonce = hc.seq[:]
// 			}
// 			payload = payload[explicitNonceLen:]

// 			additionalData := hc.additionalData[:]
// 			if hc.version == VersionTLS13 {
// 				additionalData = record[:recordHeaderLen]
// 			} else {
// 				copy(additionalData, hc.seq[:])
// 				copy(additionalData[8:], record[:3])
// 				n := len(payload) - c.Overhead()
// 				additionalData[11] = byte(n >> 8)
// 				additionalData[12] = byte(n)
// 			}

// 			var err error
// 			plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
// 			if err != nil {
// 				return nil, 0, alertBadRecordMAC
// 			}
// 		case cbcMode:
// 			blockSize := c.BlockSize()
// 			minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)
// 			if len(payload)%blockSize != 0 || len(payload) < minPayload {
// 				return nil, 0, alertBadRecordMAC
// 			}

// 			if explicitNonceLen > 0 {
// 				c.SetIV(payload[:explicitNonceLen])
// 				payload = payload[explicitNonceLen:]
// 			}
// 			c.CryptBlocks(payload, payload)

// 			// In a limited attempt to protect against CBC padding oracles like
// 			// Lucky13, the data past paddingLen (which is secret) is passed to
// 			// the MAC function as extra data, to be fed into the HMAC after
// 			// computing the digest. This makes the MAC roughly constant time as
// 			// long as the digest computation is constant time and does not
// 			// affect the subsequent write, modulo cache effects.
// 			paddingLen, paddingGood = extractPadding(payload)
// 		default:
// 			panic("unknown cipher type")
// 		}

// 		if hc.version == VersionTLS13 {
// 			if typ != recordTypeApplicationData {
// 				return nil, 0, alertUnexpectedMessage
// 			}
// 			if len(plaintext) > maxPlaintext+1 {
// 				return nil, 0, alertRecordOverflow
// 			}
// 			// Remove padding and find the ContentType scanning from the end.
// 			for i := len(plaintext) - 1; i >= 0; i-- {
// 				if plaintext[i] != 0 {
// 					typ = recordType(plaintext[i])
// 					plaintext = plaintext[:i]
// 					break
// 				}
// 				if i == 0 {
// 					return nil, 0, alertUnexpectedMessage
// 				}
// 			}
// 		}
// 	} else {
// 		plaintext = payload
// 	}

// 	if hc.mac != nil {
// 		macSize := hc.mac.Size()
// 		if len(payload) < macSize {
// 			return nil, 0, alertBadRecordMAC
// 		}

// 		n := len(payload) - macSize - paddingLen
// 		n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n) // if n < 0 { n = 0 }
// 		record[3] = byte(n >> 8)
// 		record[4] = byte(n)
// 		remoteMAC := payload[n : n+macSize]
// 		localMAC := hc.mac.MAC(hc.seq[0:], record[:recordHeaderLen], payload[:n], payload[n+macSize:])

// 		// This is equivalent to checking the MACs and paddingGood
// 		// separately, but in constant-time to prevent distinguishing
// 		// padding failures from MAC failures. Depending on what value
// 		// of paddingLen was returned on bad padding, distinguishing
// 		// bad MAC from bad padding can lead to an attack.
// 		//
// 		// See also the logic at the end of extractPadding.
// 		macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
// 		if macAndPaddingGood != 1 {
// 			return nil, 0, alertBadRecordMAC
// 		}

// 		plaintext = payload[:n]
// 	}

// 	hc.incSeq()
// 	return plaintext, typ, nil
// }

func (c *tcpCon) Read(b []byte) (n int, err error) {
	// 数据为空才等待数据写入, 否则直接读
	if c.rbuf.Len() == 0 {
		<-c.rdone
	}
	n, err = c.rbuf.Read(b)
	if err == nil {
		printMsgType(b[:n])
	}
	return n, err
}
func (c *tcpCon) Write(b []byte) (n int, err error) {
	// 未写入数据，或者已经读完所有数据才能继续写
	if c.wbuf.Len() == 0 {
		n, err = c.wbuf.Write(b)
		c.wdone <- 1
	}
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

func printMsgType(b []byte) {
	buf := new(bytes.Buffer)
	buf.Write(b)
	if buf.Len() < 4 {
		fmt.Println("data format error")
		return
	}
	data := buf.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > 65536 { // maximum handshake we support (protocol max is 16 MB)
		fmt.Printf("tls: handshake message of length %d bytes exceeds maximum of %d bytes\n", n, 65536)
		return
	}
	data = buf.Next(4 + n)
	switch data[0] {
	case typeHelloRequest:
		fmt.Println("typeHelloRequest")
	case typeClientHello:
		fmt.Println("typeClientHello")
	case typeServerHello:
		fmt.Println("typeServerHello")
	case typeNewSessionTicket:
		fmt.Println("typeNewSessionTicket")
	case typeCertificate:
		fmt.Println("typeCertificate")
	case typeCertificateRequest:
		fmt.Println("typeCertificateRequest")
	case typeCertificateStatus:
		fmt.Println("typeCertificateStatus")
	case typeServerKeyExchange:
		fmt.Println("typeServerKeyExchange")
	case typeServerHelloDone:
		fmt.Println("typeServerHelloDone")
	case typeClientKeyExchange:
		fmt.Println("typeClientKeyExchange")
	case typeCertificateVerify:
		fmt.Println("typeCertificateVerify")
	case typeFinished:
		fmt.Println("typeFinished")
	case typeEncryptedExtensions:
		fmt.Println("typeEncryptedExtensions")
	case typeEndOfEarlyData:
		fmt.Println("typeEndOfEarlyData")
	case typeKeyUpdate:
		fmt.Println("typeKeyUpdate")
	default:
		fmt.Println("unknow: todo get type")
	}
}

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
	return tlsConf, nil
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
	// server write and client read
	var s2c = new(bytes.Buffer)
	// client wirte and server read
	var c2s = new(bytes.Buffer)
	// server和client交替写，即每次只有一个人写，读也是同理
	var ch = make(chan int, 1)
	sc := &tcpCon{
		local:  "127.0.0.1",
		remote: "172.18.16.51",
		wbuf:   s2c,
		rbuf:   c2s,
		wdone:  ch,
		rdone:  ch,
	}
	cs := &tcpCon{
		local:    "127.0.0.1",
		remote:   "172.18.16.51",
		wbuf:     c2s,
		rbuf:     s2c,
		wdone:    ch,
		rdone:    ch,
		isClient: true,
	}
	sconf, err := serverTLSConf("ca.crt", "ca.key")
	// sconf.ClientAuth = tls.RequireAndVerifyClientCert
	sconf.InsecureSkipVerify = true
	if err != nil {
		fmt.Println("init server tls conf", err)
		return
	}
	cconf, err := clientTLSConf("ca.crt", "ca.key")
	if err != nil {
		fmt.Println("init client tls conf", err)
		return
	}
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
		// fmt.Printf("client: %+v\n", client.ConnectionState())
		wg.Done()
	}()
	// server
	go func() {
		if err := server.Handshake(); err != nil {
			fmt.Println("server handshake", err)
			wg.Done()
			return
		}
		// fmt.Printf("server: %+v\n", server.ConnectionState())
		wg.Done()
	}()
	wg.Wait()
	close(ch)
}
