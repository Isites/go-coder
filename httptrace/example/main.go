package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	xtrace "net/http/httptrace"
	"time"

	"github.com/Isites/go-coder/httptrace"
)

func main() {

	trace := httptrace.New("ReqTest")
	reqCtx, _ := context.WithTimeout(context.Background(), 800*time.Millisecond)
	// 增加请求trace
	traceCtx := xtrace.WithClientTrace(reqCtx, trace.ClientTrace)
	transsionReq, err := http.NewRequestWithContext(traceCtx, "GET", "http://www.baidu.com", nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	rsp, err := http.DefaultClient.Do(transsionReq)
	trace.End()
	if err == nil {
		io.CopyN(io.Discard, rsp.Body, 2<<10)
		rsp.Body.Close()
	}
}
