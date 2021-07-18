package main

import (
	"fmt"
	"reflect"
	"unsafe"
)

type mySlice struct {
	data uintptr
	len  int
	cap  int
}

func otherOP(a, b *int) {
	// 确保逃逸到堆
	reflect.ValueOf(a)
	reflect.ValueOf(b)
}

func main() {
	// 切片强转为结构体
	s := mySlice{}
	fmt.Println(fmt.Sprintf("%+v", s))
	s1 := make([]int, 10)
	s1[2] = 2
	fmt.Println(fmt.Sprintf("%+v, len(%d), cap(%d)", s1, len(s1), cap(s1)))
	s = *(*mySlice)(unsafe.Pointer(&s1))
	fmt.Println(fmt.Sprintf("%+v", s))
	fmt.Printf("%p, %v\n", s1, unsafe.Pointer(s.data))

	// 修改数组中的值
	//Data强转为一个数组
	s2 := (*[5]int)(unsafe.Pointer(s.data))
	s3 := (*[10]int)(unsafe.Pointer(s.data))
	// 修改数组中的数据后切片中对应位置的值也发生了变化
	s2[4] = 4
	fmt.Println(s1)
	fmt.Println(*s2)
	fmt.Println(*s3)

	// 结构体转为切片
	var (
		// 一个长度为5的数组
		dt [5]int
		s4 []int
	)
	s5 := mySlice{
		// 将数组地址赋值给data
		data: uintptr(unsafe.Pointer(&dt)),
		len:  2,
		cap:  5,
	}
	// 结构体强转为切片
	s4 = *((*[]int)(unsafe.Pointer(&s5)))
	fmt.Println(s4, len(s4), cap(s4))
	// 修改数组中的值， 切片内容也会发生变化
	dt[1] = 3
	fmt.Println(dt, s4)

	// 为什么不安全
	var (
		a = new(int)
		b = new(int)
	)
	otherOP(a, b)
	*(*int)(unsafe.Pointer(uintptr(unsafe.Pointer(a)) + unsafe.Sizeof(int(*a)))) = 1
	fmt.Println(*a, *b)

}
