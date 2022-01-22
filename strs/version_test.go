package main

import (
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

func CompareVersionNoSplit(ver1, ver2 string) (ret int) {
	defer func() {
		if ret > 0 {
			ret = 1
		} else if ret < 0 {
			ret = -1
		}
	}()
	if ver1 == ver2 {
		return 0
	}
	rv1, rv2 := []rune(ver1), []rune(ver2)
	var (
		l1, l2 = len(ver1), len(ver2)
		i, j   = 0, 0
	)
	for i < l1 && j < l2 {
		if rv1[i] == rv2[j] {
			i++
			j++
			continue
		}
		k := diffPart(i, rv1)
		rv1Str := string(rv1[i:k])
		curV1, e1 := strconv.Atoi(rv1Str)
		i = k
		k = diffPart(j, rv2)
		rv2Str := string(rv2[j:k])
		curV2, e2 := strconv.Atoi(rv2Str)
		j = k
		if e1 != nil || e2 != nil {
			ret = strings.Compare(rv1Str, rv2Str)
		} else {
			ret = curV1 - curV2
		}
		if ret != 0 {
			return ret
		}
	}
	if i < l1 {
		ret = 1
	} else if j < l2 {
		ret = -1
	}
	return ret
}

func diffPart(i int, rv []rune) (j int) {
	j = i
	for j = i; j < len(rv); j++ {
		// if rv[j] == '0' {
		// 	offset++
		// }
		if rv[j] == '.' {
			return j
		}
	}
	return j
}

// CompareVersion 比较两个appversion的大小
// return 0 means ver1 == ver2
// return 1 means ver1 > ver2
// return -1 means ver1 < ver2
func CompareVersion(ver1, ver2 string) int {
	// fast path
	if ver1 == ver2 {
		return 0
	}
	// slow path
	vers1 := strings.Split(ver1, ".")
	vers2 := strings.Split(ver2, ".")
	v1l, v2l := len(vers1), len(vers2)
	for i := 0; i < v1l && i < v2l; i++ {
		a, e1 := strconv.Atoi(vers1[i])
		b, e2 := strconv.Atoi(vers2[i])
		res := 0
		// 如果不能转换为数字，使用go默认的字符串比较
		if e1 != nil || e2 != nil {
			res = strings.Compare(vers1[i], vers2[i])
		} else {
			res = a - b
		}
		// 根据比较结果进行返回， 如果res=0，则此部分相等
		if res > 0 {
			return 1
		} else if res < 0 {
			return -1
		}
	}
	// 最后谁仍有剩余，则谁大
	if v1l > v2l {
		return 1
	} else if v1l < v2l {
		return -1
	}
	return 0
}

type cmVal struct {
	iv int
	sv string
	// 能否转换为整形
	canInt bool
}

func strs2cmVs(strs []string) []*cmVal {
	cmvs := make([]*cmVal, 0, len(strs))
	for _, v := range strs {
		it, e := strconv.Atoi(v)
		// 全部数据都保存
		cmvs = append(cmvs, &cmVal{it, v, e == nil})
	}
	return cmvs
}

var (
	lruC, _ = lru.New(500)
	slru    = NewLRU(10)
)

// CompareVersion 比较两个appversion的大小
// return 0 means ver1 == ver2
// return 1 means ver1 > ver2
// return -1 means ver1 < ver2
func CompareVersionWithCache1(ver1, ver2 string) int {
	// fast path
	if ver1 == ver2 {
		return 0
	}
	// slow path
	var (
		cmv1, cmv2             []*cmVal
		cmv1Exists, cmv2Exists bool
		expire                 int64 = 200 * 60
	)
	// read cache 1
	cmv, cmvExists := Get(ver1)
	if cmvExists {
		cmv1, cmv1Exists = cmv.([]*cmVal)
	}
	if !cmv1Exists {
		// set val and cache
		cmv1 = strs2cmVs(strings.Split(ver1, "."))
		Set(ver1, cmv1, time.Now().Unix()+expire)
	}
	// read cache 2
	cmv, cmvExists = Get(ver2)
	if cmvExists {
		cmv2, cmv2Exists = cmv.([]*cmVal)
	}
	if !cmv2Exists {
		// set val and cache
		cmv2 = strs2cmVs(strings.Split(ver2, "."))
		Set(ver2, cmv2, time.Now().Unix()+expire)
	}
	// compare ver str
	v1l, v2l := len(cmv1), len(cmv2)
	for i := 0; i < len(cmv1) && i < len(cmv2); i++ {
		res := 0
		// can use int compare
		if cmv1[i].canInt && cmv2[i].canInt {
			res = cmv1[i].iv - cmv2[i].iv
		} else {
			res = strings.Compare(cmv1[i].sv, cmv2[i].sv)
		}
		if res > 0 {
			return 1
		} else if res < 0 {
			return -1
		}
	}
	if v1l > v2l {
		return 1
	} else if v1l < v2l {
		return -1
	}
	return 0
}

func CompareVersionWithCache2(ver1, ver2 string) int {
	// fast path
	if ver1 == ver2 {
		return 0
	}
	// slow path
	var (
		cmv1, cmv2             []*cmVal
		cmv1Exists, cmv2Exists bool
		// expire                 int64 = 200 * 60
	)
	// read cache 1
	cmv, cmvExists := lruC.Get(ver1)
	if cmvExists {
		cmv1, cmv1Exists = cmv.([]*cmVal)
	}
	if !cmv1Exists {
		// set val and cache
		cmv1 = strs2cmVs(strings.Split(ver1, "."))
		lruC.Add(ver1, cmv1)
	}
	// read cache 2
	cmv, cmvExists = lruC.Get(ver2)
	if cmvExists {
		cmv2, cmv2Exists = cmv.([]*cmVal)
	}
	if !cmv2Exists {
		// set val and cache
		cmv2 = strs2cmVs(strings.Split(ver2, "."))
		lruC.Add(ver2, cmv2)
	}
	// compare ver str
	v1l, v2l := len(cmv1), len(cmv2)
	for i := 0; i < len(cmv1) && i < len(cmv2); i++ {
		res := 0
		// can use int compare
		if cmv1[i].canInt && cmv2[i].canInt {
			res = cmv1[i].iv - cmv2[i].iv
		} else {
			res = strings.Compare(cmv1[i].sv, cmv2[i].sv)
		}
		if res > 0 {
			return 1
		} else if res < 0 {
			return -1
		}
	}
	if v1l > v2l {
		return 1
	} else if v1l < v2l {
		return -1
	}
	return 0
}

func CompareVersionWithCache3(ver1, ver2 string) int {
	// fast path
	if ver1 == ver2 {
		return 0
	}
	// slow path
	var (
		cmv1, cmv2             []*cmVal
		cmv1Exists, cmv2Exists bool
		// expire                 int64 = 200 * 60
	)
	// read cache 1
	cmv, cmvExists := slru.Get(ver1)
	if cmvExists {
		cmv1, cmv1Exists = cmv.([]*cmVal)
	}
	if !cmv1Exists {
		// set val and cache
		cmv1 = strs2cmVs(strings.Split(ver1, "."))
		slru.Set(ver1, cmv1)
	}
	// read cache 2
	cmv, cmvExists = slru.Get(ver2)
	if cmvExists {
		cmv2, cmv2Exists = cmv.([]*cmVal)
	}
	if !cmv2Exists {
		// set val and cache
		cmv2 = strs2cmVs(strings.Split(ver2, "."))
		slru.Set(ver2, cmv2)
	}
	// compare ver str
	v1l, v2l := len(cmv1), len(cmv2)
	for i := 0; i < len(cmv1) && i < len(cmv2); i++ {
		res := 0
		// can use int compare
		if cmv1[i].canInt && cmv2[i].canInt {
			res = cmv1[i].iv - cmv2[i].iv
		} else {
			res = strings.Compare(cmv1[i].sv, cmv2[i].sv)
		}
		if res > 0 {
			return 1
		} else if res < 0 {
			return -1
		}
	}
	if v1l > v2l {
		return 1
	} else if v1l < v2l {
		return -1
	}
	return 0
}

func TestMain(m *testing.M) {
	f, _ := os.Create("compare_ver.pprof")
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()
	m.Run()
}

func BenchmarkCompareVersion(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompareVersion("7.0.09.000", "7.0.09")
		CompareVersion("7.0.08.9999", "7.0.09.9999")
		CompareVersion("9.01", "9.0")
	}
}

// func BenchmarkCompareVersionWithCache1(b *testing.B) {
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		CompareVersionWithCache1("7.0.09.000", "7.0.09")
// 		CompareVersionWithCache1("7.0.08.9999", "7.0.09.9999")
// 		CompareVersionWithCache1("9.01", "9.0")
// 	}
// }

// func BenchmarkCompareVersionWithCache2(b *testing.B) {
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		CompareVersionWithCache2("7.0.09.000", "7.0.09")
// 		CompareVersionWithCache2("7.0.08.9999", "7.0.09.9999")
// 		CompareVersionWithCache2("9.01", "9.0")
// 	}
// }

func BenchmarkCompareVersionWithCache3(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompareVersionWithCache3("7.0.09.000", "7.0.09")
		CompareVersionWithCache3("7.0.08.9999", "7.0.09.9999")
		CompareVersionWithCache3("9.01", "9.0")
	}
}

func BenchmarkCompareVersionNoSplit(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompareVersionNoSplit("7.0.09.000", "7.0.09")
		CompareVersionNoSplit("7.0.08.9999", "7.0.09.9999")
		CompareVersionNoSplit("9.01", "9.0")
	}
}

// func BenchmarkSplit(b *testing.B) {
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		strings.Split("7.0.09.000", ".")
// 		strings.Split("7.0.09", ".")
// 		strings.Split("9.01", ".")
// 	}
// }

// func BenchmarkFieldsFunc(b *testing.B) {
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		strings.FieldsFunc("7.0.09.000", func(r rune) bool { return r == '.' })
// 		strings.FieldsFunc("7.0.09", func(r rune) bool { return r == '.' })
// 		strings.FieldsFunc("9.01", func(r rune) bool { return r == '.' })
// 	}
// }
