package main

import (
	"fmt"

	"github.com/shopspring/decimal"
)

// 表示小数位保留8位精度
const prec = 100000000

var decimalPrec = decimal.NewFromFloat(prec)

func float2Int(f float64) int64 {
	return decimal.NewFromFloat(f).Mul(decimalPrec).IntPart()
}

func int2float(i int64) float64 {
	return float64(i) / prec
}

func main() {
	// 1元钱分给3个人，每个人分多少？
	var m float64 = float64(1) / 3
	fmt.Println(m, m+m+m)
	// 最后一人分得的钱使用减法
	m3 := 1 - m - m
	fmt.Println(m3, m+m+m3)
	// var (
	// 	a float64 = 123456789012345.678
	// 	b float64 = 1.23456789012345678
	// )

	// fmt.Println(a, b, decimal.NewFromFloat(a), a == 123456789012345.67)
	var (
		// 广告平台总共收入7.11美元
		fee float64 = 7.1100
		// 以下是不同渠道带来的点击数
		clkDetails = []int64{220, 127, 172, 1, 17, 1039, 1596, 200, 236, 151, 91, 87, 378, 289, 2, 14, 4, 439, 1, 2373, 90}
		totalClk   int64
	)
	// 计算所有渠道带来的总点击数
	for _, c := range clkDetails {
		totalClk += c
	}
	var (
		floatTotal float64
		// 以浮点数计算每次点击的收益
		floatCPC float64 = fee / float64(totalClk)
		intTotal int64
		// 以8位精度的整形计算每次点击的收益(每次点击收益转为整形)
		intCPC        int64 = float2Int(fee / float64(totalClk))
		intFloatTotal float64
		// 以8位进度的整形计算每次点击的收益(每次点击收益保留为浮点型)
		intFloatCPC  float64 = float64(float2Int(fee)) / float64(totalClk)
		decimalTotal         = decimal.Zero
		// 以decimal计算每次点击收益
		decimalCPC = decimal.NewFromFloat(fee).Div(decimal.NewFromInt(totalClk))
	)
	// 计算各渠道点击收益，并累加
	for _, c := range clkDetails {
		floatTotal += floatCPC * float64(c)
		intTotal += intCPC * c
		intFloatTotal += intFloatCPC * float64(c)
		decimalTotal = decimalTotal.Add(decimalCPC.Mul(decimal.NewFromInt(c)))
	}
	// 累加结果对比
	fmt.Println(floatTotal)
	fmt.Println(intTotal)
	fmt.Println(decimal.NewFromFloat(intFloatTotal).IntPart())
	fmt.Println(decimalTotal.InexactFloat64())
}
