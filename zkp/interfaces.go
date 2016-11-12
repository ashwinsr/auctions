package zkp

import (
	"math/big"
)

type Ciphertext struct {
	alpha big.Int
	beta  big.Int
}

type Permutation struct {
	forward  []int
	backward []int
}

