package handsh

import (
	"fmt"
	"strings"
)

// KeyLog tls.Config 可通过KeyLogWriter字段打印部分密钥日志，KeyLogWriter类型为io.Writer
type KeyLog string

// Write ..
func (s KeyLog) Write(p []byte) (n int, err error) {
	fmt.Println(s, string(p))
	return len(p), nil
}

// Info ..
func (s KeyLog) Info(str string) {
	s.Write([]byte(str))
}

// Err ..
func (s KeyLog) Err(str string) {
	fmt.Println(strings.ToUpper(string(s))+" ERR:", str)
}

const (
	client = KeyLog("Client")
	server = KeyLog("Server")
)
