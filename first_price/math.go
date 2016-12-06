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

// TODO make sure right indices
// returns (result_(id))^m, [](result_(id))
func ComputeOutcome(id, j, n, k int, m *big.Int, p *big.Int, getNum func(x, y int) *big.Int) (afterExp big.Int, beforeExp []big.Int) {
	var cachedVal big.Int
	cachedVal.Set(zkp.One)
	firstResult := Multiply(1, n, p, func(h int) *big.Int {
		return Multiply(j+1, k, p, func(d int) *big.Int {
			return getNum(h, d)
		})
	})

	cachedVal.Mul(&cachedVal, firstResult)
	cachedVal.Mod(&cachedVal, p)

	for i := 0; i < n; i++ {
		var result big.Int
		result.Set(&cachedVal)

		secondResult := Multiply(1, j-1, p, func(d int) *big.Int {
			return getNum(i, d)
		})

		result.Mul(&result, secondResult)
		result.Mod(&result, p)

		thirdResult := Multiply(1, i-1, p, func(h int) *big.Int {
			return getNum(h, j)
		})

		result.Mul(&result, thirdResult)
		result.Mod(&result, p)

		// if this is our ID, we need to exponentiate as well!
		if id == i {
			afterExp.Set(&result)
			afterExp.Exp(&result, m, p)
		}

		beforeExp = append(beforeExp, result)
	}

	return
}
