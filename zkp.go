package main

import (
	"crypto/sha256"
	"math/big"
	"math/rand"
	"time"
)

// DiscreteLog generates a zero-knowledge proof of the discrete log
// problem using the Fiat–Shamir heuristic and returns the proof pair
// (t, r).
func DiscreteLog(x big.Int, g big.Int, p big.Int, q big.Int) (big.Int, big.Int) {
	// Setup a hash and PRG
	h := sha256.New()
	randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	var v, t, c, r, A big.Int

	// Compute t
	v.Rand(randGen, &q)
	t.Exp(&g, &v, &p)

	// Compute c
	byteArray := append(g.Bytes()[:], x.Bytes()[:]...)
	byteArray = append(byteArray, t.Bytes()[:]...)
	h.Write(byteArray)
	c.SetBytes(h.Sum(nil))
	c.Mod(&c, &p)

	// Calculate r = v - cx
	A.Mul(&c, &x)
	r.Sub(&v, &A)
	r.Mod(&r, &q)

	return t, r
}
