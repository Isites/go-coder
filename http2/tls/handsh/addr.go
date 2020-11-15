package handsh

// TCPAddr 简单实现net.Addr接口
type TCPAddr string

// Network ..
func (addr TCPAddr) Network() string {
	return "tcp"
}

// String ..
func (addr TCPAddr) String() string {
	return string(addr)
}
