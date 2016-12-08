package main

import (
	"math/big"

	"github.com/ashwinsr/auctions/zkp"
)

type GetIntFunc func(i int) *big.Int

// multiplies getter(start) * getter(start + 1) * ... * getter(end) mod P
func Multiply(start, end int, p *big.Int, getter GetIntFunc) *big.Int {
	var result big.Int
	result.Set(zkp.One)
	for i := start; i < end; i++ {
		result.Mul(&result, getter(i))
		result.Mod(&result, p)
	}
	return &result
}

type GetNumFunc func(x, y int) *big.Int

func Round2ComputeInitialValue(n, k, j int, p *big.Int, getNum GetNumFunc) (cachedVal big.Int) {
	cachedVal.Set(zkp.One)
	firstResult := Multiply(0, n, p, func(h int) *big.Int {
		return Multiply(j+1, k, p, func(d int) *big.Int {
			return getNum(h, d)
		})
	})

	cachedVal.Mul(&cachedVal, firstResult)
	cachedVal.Mod(&cachedVal, p)
	return
}

// TODO make sure right indices
// returns (result_(id))^m, [](result_(id))
func Round2ComputeOutcome(i, j int, p, cachedVal *big.Int, getNum GetNumFunc) big.Int {
	var result big.Int
	result.Set(cachedVal)

	// upper limit is j and this multiply function is NON-INCLUSIVE
	secondResult := Multiply(0, j, p, func(d int) *big.Int {
		return getNum(i, d)
	})

	result.Mul(&result, secondResult)
	result.Mod(&result, p)

	// TODO this part is for TIEBREAKING
	// thirdResult := Multiply(0, i, p, func(h int) *big.Int {
	// 	return getNum(h, j)
	// })

	// result.Mul(&result, thirdResult)
	// result.Mod(&result, p)

	return result
}
