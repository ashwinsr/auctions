package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

/*
 * Variable names follow THIS WIKIPEDIA ARTICLE:
 * https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
 */

// DiscreteLogKnowledge generates a ZKP of the knowledge of a discrete
// logarithm using the Fiat–Shamir heuristic and returns the proof pair
// (t, r). The total size of the ZKP is log p + log q bits.
func DiscreteLogKnowledge(x big.Int, g big.Int, p big.Int, q big.Int) (big.Int, big.Int) {
	h := sha256.New() // h can be used to calculate the sha256

	// Set up random number generator
	randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	// A is a temporary variable for below
	var v, t, c, r, A, y big.Int

	// Calculate public key from private key
	y.Exp(&g, &x, &p) // y = g^x mod p

	// Compute t
	v.Rand(randGen, &q) // v = rand() mod q
	t.Exp(&g, &v, &p) // t = g^v mod p

	// Compute c = SHA256(g,y,t)
	h.Write(g.Bytes()[:])
	h.Write(y.Bytes()[:])
	h.Write(t.Bytes()[:])
	c.SetBytes(h.Sum(nil))
	c.Mod(&c, &q) // c = c mod q

	// Calculate r = v - cx
	A.Mul(&c, &x) // A = c * x
	r.Sub(&v, &A) // r = v - c*x
	r.Mod(&r, &q) // r = r mod q

	return t, r
}

// DiscreteLogEquality generates a ZKP of the fact that the discrete
// logarithms of k values are equal using the Fiat–Shamir heuristic and
// returns the proof tuple (t[], r). The total size of the ZKP is k * log p +
// log q bits.
func DiscreteLogEquality(x big.Int, g []big.Int, p big.Int, q big.Int) ([]big.Int, big.Int) {
	h := sha256.New() // h can be used to calculate the sha256

	// Set up random number generator
	// randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	randGen := rand.New(rand.NewSource(690))

	var v, c, A, r big.Int

	// fmt.Println("G = ")
	// fmt.Println(g)

	// Compute t
	v.Rand(randGen, &q)
	t := make([]big.Int, len(g))
	Y := make([]big.Int, len(g))

	for i := 0; i < len(g); i++ {
		t[i].Exp(&g[i], &v, &p) // t[i] = g[i]^v mod p
		Y[i].Exp(&g[i], &x, &p) // Y[i] = g[i]^x mod p
	}

	// Compute c = H(g[i], Y[i], t[i])
	for i := 0; i < len(g); i++ {
		h.Write(g[i].Bytes()[:])
		h.Write(Y[i].Bytes()[:])
		h.Write(t[i].Bytes()[:])
	}

	c.SetBytes(h.Sum(nil))
	c.Mod(&c, &q) // c = c mod q

	fmt.Print("c = ")
	fmt.Println(c.String())

	// Calculate r = v - cx mod q
	A.Mul(&c, &x) // A = c*x
	r.Sub(&v, &A) // r = v - c*x
	r.Mod(&r, &q) // r = r mod q

	// one := big.NewInt(1)
	// var pMinusOne big.Int
	// pMinusOne.Sub(&p, one)
	// r.Mod(&r, &pMinusOne)

	return t, r
}
