package zkp

import (
	// "fmt"
	"math/big"
)

// var C_P = big.NewInt(5915587277)
// var C_Q = big.NewInt(1500450271)
// var C_Pprime = big.NewInt(32833)
// var C_Qprime = big.NewInt(122887)
// var C_PQ = big.NewInt(4034748871)
// var C_N = big.NewInt(8876044532898802067)

var C_P = big.NewInt(7)
var C_Q = big.NewInt(11)
var C_N = big.NewInt(77)

var C_Pprime = big.NewInt(3)
var C_Qprime = big.NewInt(5)
var C_PQ = big.NewInt(15)


func GenerateGCommitment() (g big.Int) {
	var j, phi, temp, h, C_NMinusOne, mod1, mod2 big.Int

	C_NMinusOne.Sub(C_N, One)

	// calculate (p - 1)
	phi.Sub(C_P, One)
	temp.Sub(C_Q, One)
	phi.Mul(&phi, &temp)

	j.Div(&phi, C_PQ)

	for {
		// find random number not equal to 1
		for {
			h.Rand(RandGen, &C_NMinusOne)
			if h.Cmp(One) != 0 && h.Cmp(Zero) != 0 { // TODO: Should not be 0, right?
				break
			}
		}
		g.Exp(&h, &j, C_N) // G[i] = h^j mod p
		mod1.Mod(&g, C_P)
		mod2.Mod(&g, C_Q)
		if g.Cmp(One) != 0 && mod1.Cmp(Zero) != 0 && mod2.Cmp(Zero) != 0 { // if it's not 1, we are done
			return
		}
	}
}

func GenerateGsCommitment(numGs int) (G []big.Int) {
	for i := 0; i < numGs; i++ {
		G = append(G, GenerateGCommitment())
	}

	return
}

func CreateCommitment(M []big.Int, r big.Int) (c big.Int) {
	c = *One
	G := GenerateGsCommitment(len(M) + 1)

	var temp big.Int
	for i := 0; i < len(M); i++ {
		temp.Exp(&G[i], &M[i], C_N)
		c.Mul(&c, &temp)
		c.Mod(&c, C_N)
	}

	temp.Exp(&G[len(M)], &r, C_N)
	c.Mul(&c, &temp)
	c.Mod(&c, C_N)

	return
}
