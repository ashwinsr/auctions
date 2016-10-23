package zkp

import (
	"math/big"
	"math/rand"
	"time"
)

const NumTests = 200

// TODO err... too small?
var P = big.NewInt(34531109)
var Q = big.NewInt(8632777)
var G = big.NewInt(19044154)

var One = big.NewInt(1)

var RandGen = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
