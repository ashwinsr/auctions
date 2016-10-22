package main

import (
	"crypto/sha256"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestDiscreteLogKnowledge(test *testing.T) {
	randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	for i := 0; i < NumTests; i++ {
		var x, y big.Int

		g := GenerateG(P, Q)

		// Generate private key, public key pair
		x.Rand(randGen, Q) // x = rand() mod Q // TODO also shouldn't be 0
		y.Exp(&g, &x, P)   // y = g^x mod P

		// Generate zero-knowledge proof
		t, r := DiscreteLogKnowledge(x, g, *P, *Q)

		// Verification
		h := sha256.New()
		var tv, c big.Int

		// Compute c = SHA256(g,y,t)
		h.Write(g.Bytes()[:])
		h.Write(y.Bytes()[:])
		h.Write(t.Bytes()[:])
		c.SetBytes(h.Sum(nil))
		c.Mod(&c, Q) // c = c mod Q

		// Compute tv = g^r * y^c mod P
		tv.Exp(&g, &r, P)
		c.Exp(&y, &c, P)
		tv.Mul(&tv, &c)
		tv.Mod(&tv, P)

		// So what do we have here?
		if t.Cmp(&tv) != 0 {
			test.Error("Expected " + tv.String() + ", got " + t.String())
		}
	}
}

func TestDiscreteLogEquality(test *testing.T) {
	randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	for i := 0; i < NumTests; i++ {

		// Generate private key
		var x big.Int
		x.Rand(randGen, Q)

		G := GenerateGs(P, Q, 10)

		// Generate zero-knowledge proof
		t, r := DiscreteLogEquality(x, G, *P, *Q)

		// Verification
		h := sha256.New()
		var tv, c, n big.Int

		// Compute c
		Y := make([]big.Int, len(G))
		for i := 0; i < len(G); i++ {
			Y[i].Exp(&G[i], &x, P)
			h.Write(G[i].Bytes()[:])
			h.Write(Y[i].Bytes()[:])
			h.Write(t[i].Bytes()[:])
		}

		c.SetBytes(h.Sum(nil))
		c.Mod(&c, Q) // c = c mod Q

		for i := 0; i < len(G); i++ {
			// Compute tv = g^r * y^c mod P
			tv.Exp(&G[i], &r, P)
			n.Exp(&Y[i], &c, P)
			tv.Mul(&tv, &n)
			tv.Mod(&tv, P)

			// So what do we have here?
			if t[i].Cmp(&tv) != 0 {
				test.Error("WRONG! " + G[i].String() + " Expected " + tv.String() + ", got " + t[i].String())
			} else {
				test.Log("RIGHT! " + G[i].String() + " Expected " + tv.String() + ", got " + t[i].String())
			}
		}
	}
}
