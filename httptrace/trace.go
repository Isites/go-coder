package httptrace

import (
	"crypto/tls"
	"fmt"
	"math"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"
)

type cost struct {
	st time.Time
	et time.Time
}

func (c *cost) cost() float64 {
	d := c.et.Sub(c.st)
	ms := d / time.Millisecond
	nsec := d % time.Millisecond
	ct := float64(ms) + float64(nsec)/1e6
	// 保留两位小数
	return math.Round(ct*100) / 100
}

type costDesc struct {
	field string
	cost  float64
}

func (c *costDesc) desc() string {
	if c.cost < 0 {
		return c.field + "wait failed"
	}
	if c.cost == 9.22337203685478e+12 {
		return c.field + "wait failed"
	}
	return c.field + ": " + strconv.FormatFloat(c.cost, 'f', 2, 64)
}

// TimeStat 目前只做耗时统计
type TimeStat struct {
	name    string
	endTime time.Time
	// 在回调中可能存在并发调用，所以写时间时需要加锁
	mu    sync.Mutex
	costs map[string]*cost
	// http请求过程中的回调信息
	*httptrace.ClientTrace
}

// 设置开始时间
func (t *TimeStat) setStTime(key string, time time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.costs[key]
	if !ok {
		c = &cost{}
	}
	c.st = time
	t.costs[key] = c
}

// 设置结束时间
func (t *TimeStat) setEtTime(key string, time time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.costs[key]
	if !ok {
		c = &cost{}
	}
	c.et = time
	t.costs[key] = c
}

// End 结束统计， 并输出相关信息
func (t *TimeStat) End() {
	logs := t.calcCosts()
	fmt.Printf("%s req stat start\n", t.name)
	for _, l := range logs {
		fmt.Println(l.desc())
	}
	fmt.Printf("%s req stat end\n", t.name)
}

func (t *TimeStat) calcCosts() []costDesc {
	// 每次计算时 设置结束时间，以供后续使用
	t.endTime = time.Now()
	t.setEtTime("read_cost", t.endTime)
	t.setEtTime("total", t.endTime)
	// wait_cost: 将请求数据发送至网络一直到到收到响应
	// connect_total: 建立连接
	// dns_cost: 解析dns耗时
	// write_cost: 将数据发送至网络耗时
	// read_cost: 从收到第一字节响应到trace end，这中间不包含网络数据读取
	// total，从创建请求到调用trace end
	// 按顺序输出
	costKeys := []string{"connect_total", "dns_cost", "connect", "tls_cost", "write_cost", "wait_cost", "read_cost", "total"}
	logs := make([]costDesc, 0, len(costKeys)+1)
	// logs = append(logs, log.KVString("name", t.name))
	for _, key := range costKeys {
		if c, ok := t.costs[key]; ok {
			// 按照毫秒统计耗时
			logs = append(logs, costDesc{key, c.cost()})
		}
	}
	return logs
}

// 传入请求名称
func New(name string) *TimeStat {
	ts := &TimeStat{
		name:  name,
		costs: make(map[string]*cost),
	}
	// 初始化hook
	ts.ClientTrace = &httptrace.ClientTrace{
		DNSStart:             DNSStart(ts),
		DNSDone:              DNSDone(ts),
		GetConn:              GetConn(ts),
		GotConn:              GotConn(ts),
		ConnectStart:         ConnectStart(ts),
		ConnectDone:          ConnectDone(ts),
		TLSHandshakeStart:    TLSHandshakeStart(ts),
		TLSHandshakeDone:     TLSHandshakeDone(ts),
		WroteHeaderField:     WroteHeaderField(ts),
		WroteHeaders:         WroteHeaders(ts),
		WroteRequest:         WroteRequest(ts),
		GotFirstResponseByte: GotFirstResponseByte(ts),
	}
	return ts
}

// DNSStart dns查找开始
func DNSStart(t *TimeStat) func(httptrace.DNSStartInfo) {
	return func(dsi httptrace.DNSStartInfo) {
		t.setStTime("dns_cost", time.Now())
	}
}

// DNSDone dns查找结束
func DNSDone(t *TimeStat) func(httptrace.DNSDoneInfo) {
	return func(ddi httptrace.DNSDoneInfo) {
		t.setEtTime("dns_cost", time.Now())
	}
}

// GetConn 开始获取连接
func GetConn(t *TimeStat) func(string) {
	return func(hostPort string) {
		now := time.Now()
		t.setStTime("connect_total", now)
		t.setStTime("total", now)
	}
}

// GetConn 获取连接到连接（包含连接从连接池中获取到连接）
// 如果是非服用连接则包含DNS解析时间和连接建立时间以及tls握手时间
func GotConn(t *TimeStat) func(httptrace.GotConnInfo) {
	return func(gci httptrace.GotConnInfo) {
		t.setEtTime("connect_total", time.Now())
	}
}

// ConnectStart 建立连接，可能会被多次调用
func ConnectStart(t *TimeStat) func(string, string) {
	return func(network, addr string) {
		t.setStTime("connect", time.Now())
	}
}

// ConnectDone 建立连接结束，可能会被多次调用
func ConnectDone(t *TimeStat) func(string, string, error) {
	return func(network, addr string, err error) {
		t.setEtTime("connect", time.Now())
	}
}

// TLSHandshakeStart tls开始握手
func TLSHandshakeStart(t *TimeStat) func() {
	return func() {
		t.setStTime("tls_cost", time.Now())
	}
}

// TLSHandshakeDone tls握手结束
func TLSHandshakeDone(t *TimeStat) func(tls.ConnectionState, error) {
	return func(cs tls.ConnectionState, e error) {
		t.setEtTime("tls_cost", time.Now())
	}
}

// WroteHeaderField 每次写入一个header就调用一次， 此时header并不一定写入网络
func WroteHeaderField(t *TimeStat) func(string, []string) {
	first := true
	return func(s1 string, s2 []string) {
		if first {
			t.setStTime("write_cost", time.Now())
			first = false
		}
	}
}

// WroteHeaders header 写入结束，并刷新缓冲到网络
func WroteHeaders(t *TimeStat) func() {
	return func() {}
}

// WroteRequest 所有请求写入网络结束，如果是重试请求可能会写入多次
func WroteRequest(t *TimeStat) func(httptrace.WroteRequestInfo) {
	return func(wri httptrace.WroteRequestInfo) {
		tm := time.Now()
		t.setEtTime("write_cost", tm)
		t.setStTime("wait_cost", tm)
	}
}

// GotFirstResponseByte 当读取到响应时
func GotFirstResponseByte(t *TimeStat) func() {
	return func() {
		tm := time.Now()
		t.setStTime("read_cost", tm)
		t.setEtTime("wait_cost", tm)
	}
}
