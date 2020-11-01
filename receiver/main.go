package main

import (
	"fmt"
)

type set interface {
	set1(s string)
	set2(s string)
}

type test struct {
	s string
}

func (t *test) set1(s string) {
	t.s = s
}

func (t test) set2(s string) {
	t.s = s
}

type los string

func (s los) p1() {
	fmt.Println(s)
}

func (s *los) p2() {
	fmt.Println(s)
}

func main() {
	// 例子一
	var (
		t1 test
		t2 = new(test)
	)
	t1.set1("1")
	fmt.Print(t1.s)
	t1.set2("2")
	fmt.Print(t1.s)
	t2.set1("3")
	fmt.Print(t2.s)
	t2.set2("4")
	fmt.Print(t2.s)
	fmt.Print(" ")
	_, ok1 := (interface{}(t1)).(set)
	_, ok2 := (interface{}(t2)).(set)
	fmt.Println(ok1, ok2)
	// 例子二
	var s1 los = "1111"
	var s2 *los = &s1
	const s3 los = "3333"
	s1.p1()
	s1.p2()
	s2.p1()
	s2.p2()
	s3.p1()
	// s3.p2() // 注释以防止无法运行
}
