package handsh

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

// 这里需要注意的是， ”读完一个消息才能写入另外一个消息“这个设计有缺陷
// var m int
// if len(b) > 1 && c.vers == VersionTLS10 {
// 	if _, ok := c.out.cipher.(cipher.BlockMode); ok {
// 		n, err := c.writeRecordLocked(recordTypeApplicationData, b[:1])
// 		if err != nil {
// 			return n, c.out.setErrorLocked(err)
// 		}
// 		m, b = 1, b[1:]
// 	}
// }

// n, err := c.writeRecordLocked(recordTypeApplicationData, b)
// 底层针对tls1.0有这样一个逻辑，对于大于一字节的用户数据，会写为两个recordTypeApplicationData消息

// TCPCon 简单模拟实现底层连接
type TCPCon struct {
	Local    TCPAddr
	Remote   TCPAddr
	IsClient bool
	Wbuf     *bytes.Buffer
	Rbuf     *bytes.Buffer
	Wdone    chan<- int
	Rdone    <-chan int
	Praser   *TLSMsgParser
}

// Read ..
func (c *TCPCon) Read(b []byte) (n int, err error) {
	// 数据为空才等待数据写入, 否则直接读
	if c.Rbuf.Len() == 0 {
		<-c.Rdone
	}
	n, err = c.Rbuf.Read(b)
	// raw := make([]byte, n)
	// copy(raw, b[:n])
	// c.Praser.Parse(c.IsClient, raw)
	return n, err
}

// Write ..
func (c *TCPCon) Write(b []byte) (n int, err error) {
	// 未写入数据，或者已经读完所有数据才能继续写
	log := server
	if c.IsClient {
		log = client
	}
	if c.Wbuf.Len() == 0 {
		n, err = c.Wbuf.Write(b)
		log.Info(fmt.Sprintf("write data len: %d", n))
		raw := make([]byte, n)
		copy(raw, b[:n])
		c.Praser.Parse(!c.IsClient, raw)
		c.Wdone <- 1
	}
	return n, err
}

// Close ..
func (c *TCPCon) Close() error {
	return nil
}

// LocalAddr ..
func (c *TCPCon) LocalAddr() net.Addr {
	return c.Local
}

// RemoteAddr ..
func (c *TCPCon) RemoteAddr() net.Addr {
	return c.Remote
}

// SetDeadline ..
func (c *TCPCon) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline ..
func (c *TCPCon) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline ..
func (c *TCPCon) SetWriteDeadline(t time.Time) error {
	return nil
}
