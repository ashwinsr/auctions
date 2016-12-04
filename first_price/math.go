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
func ComputeOutcome(i, j, n, k int, m *big.Int, p *big.Int, nums [][]*big.Int) *big.Int {
	var result big.Int
	result.Set(zkp.One)
	firstResult := Multiply(1, n, p, func(h int) *big.Int {
		return Multiply(j+1, k, p, func(d int) *big.Int {
			return nums[h][d]
		})
	})

	result.Mul(&result, firstResult)
	result.Mod(&result, p)

	secondResult := Multiply(1, j-1, p, func(d int) *big.Int {
		return nums[i][d]
	})

	result.Mul(&result, secondResult)
	result.Mod(&result, p)

	thirdResult := Multiply(1, i-1, p, func(h int) *big.Int {
		return nums[h][j]
	})

	result.Mul(&result, thirdResult)
	result.Mod(&result, p)

	result.Exp(&result, m, p)

	return &result
}
