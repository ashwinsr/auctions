package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

func main() {
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
	t, r := DiscreteLog(x, *g, *p, *q)

	// Verification
	h := sha256.New()
	var v, c big.Int

	// Compute c
	byteArray := append(g.Bytes()[:], x.Bytes()[:]...)
	byteArray = append(byteArray, t.Bytes()[:]...)
	h.Write(byteArray)
	c.SetBytes(h.Sum(nil))
	c.Mod(&c, p)

	// Compute g^r * y^c
	v.Exp(g, &r, p)
	c.Exp(&y, &c, p)
	v.Mul(&v, &c)
	v.Mod(&v, p)

	if t.Cmp(&v) == 0 {
		fmt.Println("Discrete Log ZKP works.")
	} else {
		fmt.Println("Something went wrong.")
	}
}
