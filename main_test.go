package main

import (
	"crypto/sha256"
	// "fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestDiscreteLogKnowledge(test *testing.T) {
	// Err.. too small?
	p := big.NewInt(34531109)
	q := big.NewInt(8632777)
	g := big.NewInt(6655320)

	randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	var x, y big.Int

	// Generate private key, public key pair
	x.Rand(randGen, q)
	y.Exp(g, &x, p)

	// Generate zero-knowledge proof
	t, r := DiscreteLogKnowledge(x, *g, *p, *q)

	// Verification
	h := sha256.New()
	var v, c big.Int

	// Compute c
	h.Write(g.Bytes()[:])
	h.Write(y.Bytes()[:])
	h.Write(t.Bytes()[:])
	c.SetBytes(h.Sum(nil))
	c.Mod(&c, p)

	// Compute g^r * y^c
	v.Exp(g, &r, p)
	c.Exp(&y, &c, p)
	v.Mul(&v, &c)
	v.Mod(&v, p)

	// So what do we have here?
	if t.Cmp(&v) != 0 {
		test.Error("Expected " + v.String() + ", got " + t.String())
	}
}

func GenerateG(l int, q big.Int) []big.Int {
	var G []big.Int
	var n, z big.Int

	randGen := rand.New(rand.NewSource(42))

	for {
		n.Rand(randGen, &q)
		flag := true
		for j := 0; j < len(G); j++ {
			z.GCD(nil, nil, &G[j], &n)
			if z.Cmp(big.NewInt(1)) != 0 {
				flag = false
				break
			}
		}
		if flag == true {
			G = append(G, n)
		}
	}
}

func TestDiscreteLogEquality(test *testing.T) {
	// Err.. too small?
	p := big.NewInt(34531109)
	q := big.NewInt(8632777)

	// randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	randGen := rand.New(rand.NewSource(420))

	var G []big.Int
	// G = make([]big.t)
	// G[0] = big.NewInt(6525162)
	// G[1] = big.NewInt(1160783)
	// G[2] = big.NewInt(3090959)
	var x big.Int

	// Generate private key
	x.Rand(randGen, q)

	for i := 0; i < 10; i++ {
		var n big.Int
		n.Rand(randGen, q)
		G = append(G, n)
	}

	// fmt.Println("G = ")
	// fmt.Println(G)

	// Generate zero-knowledge proof
	t, r := DiscreteLogEquality(x, G, *p, *q)

	// Verification
	h := sha256.New()
	var v, c, n big.Int

	// Compute c
	Y := make([]big.Int, len(G))
	for i := 0; i < len(G); i++ {
		Y[i].Exp(&G[i], &x, p)
		h.Write(G[i].Bytes()[:])
		h.Write(Y[i].Bytes()[:])
		h.Write(t[i].Bytes()[:])
	}

	c.SetBytes(h.Sum(nil))
	c.Mod(&c, p)

	for i := 0; i < len(G); i++ {
		// Compute g^r * y^c
		v.Exp(&G[i], &r, p)
		n.Exp(&Y[i], &c, p)
		v.Mul(&v, &n)
		v.Mod(&v, p)

		// So what do we have here?
		if t[i].Cmp(&v) != 0 {
			test.Error("WRONG! " + G[i].String() + " Expected " + v.String() + ", got " + t[i].String())
		} else {
			test.Log("RIGHT! " + G[i].String() + " Expected " + v.String() + ", got " + t[i].String())
		}
	}
}
