package main

import (
	"fmt"
	"unsafe"
)

type it interface {
	f()
}

type ix1 int

func (x ix1) f() {}

type ix2 map[int]int

func (x ix2) f() {}

type canC struct {
	c int
}
type blankSt struct {
	a int
	_ string
}
type canNotC struct {
	m func() int
}

func t() interface{} {
	var err *error
	return err
}

func t1() interface{} {
	return nil
}

func main() {
	// 复数之间的比较
	var c1 complex128 = complex(1, 2) // 1+2i
	var c2 complex128 = complex(3, 4) // 3+4i
	fmt.Println(c1 == c2)
	// fmt.Println(c1 >= c2) // 放开注释编译会报错

	// 结构体之间的比较
	var st1, st2 canC
	fmt.Println(st1 == st2)
	st1.c = 3
	fmt.Println(st1 == st2)
	// fmt.Println(st1 <= st2) // 放开注释编译会报错
	// 匿名结构体字段的比较
	var (
		bst1 = blankSt{1, "333"}
		bst2 = blankSt{1, "44444"}
	)
	fmt.Println(bst1 == bst2)
	// 结构体包含不可比较的类型时
	// fmt.Println(canNotC{} == canNotC{}) // 放开注释编译会报错

	// 指针之间的比较
	var arr1, arr2 [0]int
	parr1 := &arr1
	parr2 := &arr2
	fmt.Println(unsafe.Sizeof(arr1))
	fmt.Println(parr1 == parr2)
	fmt.Println(uintptr(unsafe.Pointer(parr1)), uintptr(unsafe.Pointer(parr2)))

	// 管道之间的比较
	var cint1, cint2 chan<- string
	cint3 := make(chan string, 2)
	cint4 := make(chan string, 2)
	cint5 := make(chan string)
	fmt.Println(cint1 == cint2, cint3 == cint4, cint5 == cint1)
	cint1 = cint4
	fmt.Println(cint1 == cint4)

	// interface{}之间的比较
	var (
		i1 interface{} = uint(1)
		i2 interface{} = uint(1)
		i3 interface{} = uint(3)
		i4 interface{} = int(3)
		i5 interface{} = []int{}
		i6 interface{} = map[int]string{}
		// i7 interface{} = map[int]string{}
	)
	// 变量不为nil，且均为可比较类型时
	fmt.Println(i1 == i2, i1 == i3, i3 == i4)
	// 变量不为nil，且均为不可比较类型时
	fmt.Println(i5 == i6)
	// fmt.Println(i7 == i6) //避免panic
	// interface{} 不等于nil
	fmt.Println(t() == nil, t1() == nil)

	// X类型实现了接口T，则X的变量能和T的变量t进行比较
	x1 := ix1(2)
	var t1 it = ix2{}
	// 类型不一致时
	fmt.Println(x1 == t1)
	// 类型一致时
	t1 = ix1(2)
	fmt.Println(t1 == x1)
	// interface{} 和任意可比较类型进行比较
	var it1 interface{} = "111"
	fmt.Println(it1 == 1)
	// 引起panic， 下面代码注释避免引起panic
	// var t2 it = ix2{}
	// var t3 it = ix2{}
	// fmt.Println(t2 == t3)

	// 数组间的比较
	// 类型相同但元素不可比较
	// var array1 [3][]int
	// var array2 [3][]int
	// fmt.Println(array1 == array2)
	//类型可比较元素不想等
	// var array3 [3]int
	// var array4 [2]int
	// fmt.Println(array3 == array4)
	// 数组可比较时
	var array5, array6 [3]int
	fmt.Println(array5 == array6)
	array5 = [...]int{3, 2, 1}
	array6 = [...]int{1, 2, 3}
	fmt.Println(array5 == array6)

}
