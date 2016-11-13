package zkp

import (
	"math/big"
)

type Ciphertext struct {
	Alpha big.Int
	Beta  big.Int
}

type Permutation struct {
	forward  []int
	backward []int
}
