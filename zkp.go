package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

// DiscreteLogKnowledge generates a ZKP of the knowledge of a discrete
// logarithm using the Fiat–Shamir heuristic and returns the proof pair
// (t, r). The total size of the ZKP is log p + log q bits.
func DiscreteLogKnowledge(x big.Int, g big.Int, p big.Int, q big.Int) (big.Int, big.Int) {
	// Setup a hash and PRG
	h := sha256.New()
	randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	var v, t, c, r, A, y big.Int
	y.Exp(&g, &x, &p)

	// Compute t
	v.Rand(randGen, &q)
	t.Exp(&g, &v, &p)

	// Compute c
	h.Write(g.Bytes()[:])
	h.Write(y.Bytes()[:])
	h.Write(t.Bytes()[:])
	c.SetBytes(h.Sum(nil))
	c.Mod(&c, &p)

	// Calculate r = v - cx
	A.Mul(&c, &x)
	r.Sub(&v, &A)
	r.Mod(&r, &q)

	return t, r
}

// DiscreteLogEquality generates a ZKP of the fact that the discrete
// logarithms of k values are equal using the Fiat–Shamir heuristic and
// returns the proof tuple (t[], r). The total size of the ZKP is k * log p +
// log q bits.
// func DiscreteLogEquality(x big.Int, g []big.Int, p big.Int, q big.Int) ([]big.Int, big.Int) {
//   // Setup a hash and PRG
//   h := sha256.New()
//   // randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
//   randGen := rand.New(rand.NewSource(690))
//
//   var v, c, A, r big.Int
//
//   // fmt.Println("G = ")
//   // fmt.Println(g)
//
//   // Compute t
//   v.Rand(randGen, &q)
//   t := make([]big.Int, len(g))
//   Y := make([]big.Int, len(g))
//
//   for i := 0; i < len(g); i++ {
//     t[i].Exp(&g[i], &v, &p)
//     Y[i].Exp(&g[i], &x, &p)
//   }
//
//   // Compute c
//   for i := 0; i < len(g); i++ {
//     h.Write(g[i].Bytes()[:])
//     h.Write(Y[i].Bytes()[:])
//     h.Write(t[i].Bytes()[:])
//   }
//
//   c.SetBytes(h.Sum(nil))
//   c.Mod(&c, &p)
//
//   // fmt.Print("c = ")
//   // fmt.Println(c.String())
//
//   // Calculate r = v - cx
//   A.Mul(&c, &x)
//   r.Sub(&v, &A)
//   r.Mod(&r, &q)
//
//   return t, r
// }

func DiscreteLogEquality(x big.Int, g1 big.Int, g2 big.Int, p big.Int, q big.Int) (big.Int, big.Int, big.Int) {
	// Setup a hash and PRG
	h := sha256.New()
	// randGen := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	randGen := rand.New(rand.NewSource(690))

	var z, c, a, b, y1, y2, r big.Int
	var temp big.Int

	// fmt.Println("G = ")
	// fmt.Println(g)

	// Compute t
	z.Rand(randGen, &q)

	// t := make([]big.Int, len(g))
	// Y := make([]big.Int, len(g))
	y1.Exp(&g1, &x, &p)
	y2.Exp(&g2, &x, &p)

	fmt.Print("y1 = ")
	fmt.Println(y1.String())
	fmt.Print("y2 = ")
	fmt.Println(y2.String())

	// for i := 0; i < len(g); i++ {
	//   t[i].Exp(&g[i], &v, &p)
	//   Y[i].Exp(&g[i], &x, &p)
	// }
	a.Exp(&g1, &z, &p)
	b.Exp(&g2, &z, &p)

	h.Write(g1.Bytes()[:])
	h.Write(g2.Bytes()[:])
	h.Write(y1.Bytes()[:])
	h.Write(y2.Bytes()[:])
	h.Write(a.Bytes()[:])
	h.Write(b.Bytes()[:])

	// Compute c
	// for i := 0; i < len(g); i++ {
	//
	//   h.Write(g[i].Bytes()[:])
	//   h.Write(Y[i].Bytes()[:])
	//   h.Write(t[i].Bytes()[:])
	// }

	c.SetBytes(h.Sum(nil))
	c.Mod(&c, &p)

	fmt.Print("c = ")
	fmt.Println(c.String())

	// Calculate r = v - cx
	temp.Mul(&c, &x)
	r.Add(&z, &temp)
	r.Mod(&r, &q)

	return a, b, r
}
