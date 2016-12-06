package zkp

import (
	"math/big"
	"math/rand"
	"time"
)

const NumTests = 10

// TODO err... too small?
var P = big.NewInt(34531109)
var Q = big.NewInt(8632777)
var G = big.NewInt(19044154)

// TODO millionaire specific
// TODO different than G LOL
var Y_Mill = big.NewInt(19044154)
var K_Mill uint = 64

var Zero = big.NewInt(0)
var One = big.NewInt(1)
var Two = big.NewInt(2)
var Three = big.NewInt(3)
var FortyTwo = big.NewInt(42)

var Lt = big.NewInt(1024)
var Ls = big.NewInt(1024)
var Lr = big.NewInt(8632777)

var RandGen = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
