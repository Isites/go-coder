package main

import (
	"fmt"

	"github.com/Isites/go-coder/types/ttt"
)

type blankSt struct {
	a int
	_ string
}

type blankSt1 struct {
	a int `json:"a"`
	_ string
}

type (
	m1 map[int]string
	m2 m1
)

type (
	str1 string
	str2 str1

	int1 int
)

type st1 struct {
	F string
}

type st2 struct {
	F string
	a string
}

func main() {

	// defined type 可赋值
	var map1 map[int]string = make(map[int]string)
	var map2 m1 = map1
	fmt.Println(map2)
	// defined type 不可赋值
	var map3 m2 = map1
	fmt.Println(map3)
	// var map4 m2 = map2 // 注释程保证程序的运行

	// 通道赋值
	var c1 chan int = make(chan int)
	var c2 chan<- int = c1
	fmt.Println(c2 == c1)
	// c1 = c2 // 注释程保证程序的运行

	//无类型常量和string
	const s1 = "1111"
	// 无类型常量string赋值
	var s3 str1 = s1
	var s4 str2 = s1
	fmt.Println(s3, s4)
	const s2 string = "1111"
	// var s5 str1 = s2 // 注释程保证程序的运行

	// var i1 int = 1 // 注释程保证程序的运行
	const i2 int = 1
	// var i3 int1 = i1 // 注释程保证程序的运行
	// var i4 int1 = i2 // 注释程保证程序的运行

	// 结构体类型相等

	// 相同包，不同tag
	// bst11 := struct {
	// 	a int
	// 	_ string
	// }{1, "555"}
	// var bst12 blankSt1 = bst11 // 注释程保证程序的运行
	// 不同包，所字段均导出
	var st11 st1 = ttt.A
	fmt.Println(st11)
	// 不同包，有字段未导出
	// var st21 st2 = ttt.B // 注释程保证程序的运行
	// fmt.Println(st21) // 注释程保证程序的运行

	bst1 := blankSt{1, "333"}
	bst2 := struct {
		a int
		_ string
	}{1, "555"}
	fmt.Println(bst1 == bst2)
}
