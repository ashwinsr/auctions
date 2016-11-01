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

// TODO millionaire specific
// TODO different than G LOL
var Y_Mill = big.NewInt(19044154)
var K_Mill uint = 64

var One = big.NewInt(1)
var FortyTwo = big.NewInt(42)

var RandGen = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
