package handsh

import (
	"crypto/rand"
)

// Rand 自定义tls.Config中生成随机数的逻辑
type Rand struct {
	RandomMode bool
}

// Read 这里为了方便调试返回固定的随机数
func (r *Rand) Read(p []byte) (n int, err error) {
	if r.RandomMode {
		return rand.Reader.Read(p)
	}
	bts := []byte("09dae1aa3d2a90d3c076b8adb23988116f62e003ae8f2c763443c9e24aab3b04")
	bts = append(bts, "2a0071514f632c21c064fa7e95d25246802a9086f533a19cf65628812e33361b"...)
	bts = append(bts, "3c4b50be833eed78e0b4827b3e427a614764700c724d323147514e8ae3576a35"...)
	bts = append(bts, "aaff6568490bce6046928b119b63fac6c187ed1a59559b4d896c6958c253e9c9"...)
	n = copy(p, bts[:len(p)])
	return n, nil
}
