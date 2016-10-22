package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestDiscreteLogKnowledge(test *testing.T) {
	// TODO Err.. too small?
	// ZKP constants
	p := big.NewInt(34531109)
	q := big.NewInt(8632777)
	g := big.NewInt(6655320) // TODO needs to be a generator

	randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	for i := 0; i < 50; i++ {
		var x, y big.Int

		// Generate private key, public key pair
		x.Rand(randGen, q) // x = rand() mod q // TODO also shouldn't be 0
		y.Exp(g, &x, p) // y = g^x mod p

		// Generate zero-knowledge proof
		t, r := DiscreteLogKnowledge(x, *g, *p, *q)

		// Verification
		h := sha256.New()
		var tv, c big.Int

		// Compute c = SHA256(g,y,t)
		h.Write(g.Bytes()[:])
		h.Write(y.Bytes()[:])
		h.Write(t.Bytes()[:])
		c.SetBytes(h.Sum(nil))
		c.Mod(&c, q) // c = c mod q

		// Compute tv = g^r * y^c mod p
		tv.Exp(g, &r, p)
		c.Exp(&y, &c, p)
		tv.Mul(&tv, &c)
		tv.Mod(&tv, p)

		// So what do we have here?
		if t.Cmp(&tv) != 0 {
			test.Error("Expected " + tv.String() + ", got " + t.String())
		}
	}
}

func GenerateG(p *big.Int, q *big.Int, numGs int) []big.Int {
	var G []big.Int
	var j, pMinusOne, h big.Int

	pMinusOne.Sub(p, one)
	j.Div(&pMinusOne, q)

	randGen := rand.New(rand.NewSource(42))

	for i := 0; i < numGs; i++ {
		for {
			var temp big.Int
			G = append(G, temp)
			// find random number not equal to 1
			for {
				h.Rand(randGen, &pMinusOne)
				if h.Cmp(one) != 0 {
					break
				}
			}
			G[i].Exp(&h, &j, p) // G[i] = h^j mod p
			if G[i].Cmp(one) != 0 { // if it's not 1, we are done
				break
			}
		}
	}
	return G
}

func TestDiscreteLogEquality(test *testing.T) {
	// Err.. too small?
	p := big.NewInt(34531109)
	q := big.NewInt(8632777)

	randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	// randGen := rand.New(rand.NewSource(420))

	// G = make([]big.t)
	// G[0] = big.NewInt(6525162)
	// G[1] = big.NewInt(1160783)
	// G[2] = big.NewInt(3090959)

	// Generate private key
	var x big.Int
	x.Rand(randGen, q)

	// Generate all the g's (bases of the exponentiation)
	// for i := 0; i < 10; i++ {
	// 	var n big.Int
	// 	n.Rand(randGen, q)
	// 	G = append(G, n)
	// }

	G := GenerateG(p, q, 10)

	// fmt.Println("G = ")
	// fmt.Println(G)

	// Generate zero-knowledge proof
	t, r := DiscreteLogEquality(x, G, *p, *q)

	// Verification
	h := sha256.New()
	var tv, c, n big.Int

	// Compute c
	Y := make([]big.Int, len(G))
	for i := 0; i < len(G); i++ {
		Y[i].Exp(&G[i], &x, p)
		h.Write(G[i].Bytes()[:])
		h.Write(Y[i].Bytes()[:])
		h.Write(t[i].Bytes()[:])
	}

	c.SetBytes(h.Sum(nil))
	c.Mod(&c, q) // c = c mod q

	fmt.Print("c = ")
	fmt.Println(c.String())

	for i := 0; i < len(G); i++ {
		// Compute tv = g^r * y^c mod p
		tv.Exp(&G[i], &r, p)
		n.Exp(&Y[i], &c, p)
		tv.Mul(&tv, &n)
		tv.Mod(&tv, p)

		// So what do we have here?
		if t[i].Cmp(&tv) != 0 {
			test.Error("WRONG! " + G[i].String() + " Expected " + tv.String() + ", got " + t[i].String())
		} else {
			test.Log("RIGHT! " + G[i].String() + " Expected " + tv.String() + ", got " + t[i].String())
		}
	}
}
