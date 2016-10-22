package zkp

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

/*
 * Variable names follow THIS WIKIPEDIA ARTICLE:
 * https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
 */

func computeCSingle(g big.Int, y big.Int, t big.Int, q big.Int) (c big.Int) {
	// Verification
	h := sha256.New()

	// Compute c = SHA256(g,y,t) mod q
	h.Write(g.Bytes()[:])
	h.Write(y.Bytes()[:])
	h.Write(t.Bytes()[:])
	c.SetBytes(h.Sum(nil))
	c.Mod(&c, &q) // c = c mod q

	return c
}

// DiscreteLogKnowledge generates a ZKP of the knowledge of a discrete
// logarithm using the Fiat–Shamir heuristic and returns the proof pair
// (t, r). The total size of the ZKP is log p + log q bits.
func DiscreteLogKnowledge(x big.Int, g big.Int, p big.Int, q big.Int) (big.Int, big.Int) {
	// A is a temporary variable for below
	var v, t, c, r, A, y big.Int

	// Calculate public key from private key
	y.Exp(&g, &x, &p) // y = g^x mod p

	// Compute t
	v.Rand(RandGen, &q) // v = rand() mod q
	t.Exp(&g, &v, &p)   // t = g^v mod p

	// Compute c = SHA256(g,y,t) mod q
	c = computeCSingle(g, y, t, q)

	// Calculate r = v - cx
	A.Mul(&c, &x) // A = c * x
	r.Sub(&v, &A) // r = v - c*x
	r.Mod(&r, &q) // r = r mod q

	return t, r
}

func computeCMany(g []big.Int, Y []big.Int, t []big.Int, q big.Int) (c big.Int) {
	h := sha256.New() // h can be used to calculate the sha256

	for i := 0; i < len(g); i++ {
		h.Write(g[i].Bytes()[:])
		h.Write(Y[i].Bytes()[:])
		h.Write(t[i].Bytes()[:])
	}

	c.SetBytes(h.Sum(nil))
	c.Mod(&c, &q) // c = c mod q

	return c
}

// DiscreteLogEquality generates a ZKP of the fact that the discrete
// logarithms of k values are equal using the Fiat–Shamir heuristic and
// returns the proof tuple (t[], r). The total size of the ZKP is k * log p +
// log q bits.
func DiscreteLogEquality(x big.Int, g []big.Int, p big.Int, q big.Int) ([]big.Int, big.Int) {
	var v, c, A, r big.Int

	// Compute t
	v.Rand(RandGen, &q)
	t := make([]big.Int, len(g))
	Y := make([]big.Int, len(g))

	for i := 0; i < len(g); i++ {
		t[i].Exp(&g[i], &v, &p) // t[i] = g[i]^v mod p
		Y[i].Exp(&g[i], &x, &p) // Y[i] = g[i]^x mod p
	}

	// Compute c = H(g[i], Y[i], t[i])
	c = computeCMany(g, Y, t, q)

	// Calculate r = v - cx mod q
	A.Mul(&c, &x) // A = c*x
	r.Sub(&v, &A) // r = v - c*x
	r.Mod(&r, &q) // r = r mod q

	return t, r
}

func GenerateGs(p *big.Int, q *big.Int, numGs int) (G []big.Int) {
	for i := 0; i < numGs; i++ {
		G = append(G, GenerateG(p, q))
	}
	return
}

func GenerateG(p *big.Int, q *big.Int) big.Int {
	var j, pMinusOne, h, g big.Int

	// calculate (p - 1)
	pMinusOne.Sub(p, One)
	j.Div(&pMinusOne, q)

	for {
		// find random number not equal to 1
		for {
			h.Rand(RandGen, &pMinusOne)
			if h.Cmp(One) != 0 {
				break
			}
		}
		g.Exp(&h, &j, p)     // G[i] = h^j mod p
		if g.Cmp(One) != 0 { // if it's not 1, we are done
			return g
		}
	}
}

// g is arbitrary generator of G_q, y is public key, t and r are the ZKP, and p and q are the primes
// TODO code quality, structs, etc...
// TODO should probably use big.Int pointers everywhere
func CheckDiscreteLogKnowledgeProof(g big.Int, y big.Int, t big.Int, r big.Int, p big.Int, q big.Int) (err error) {
	var tv big.Int

	c := computeCSingle(g, y, t, q)

	// Compute tv = g^r * y^c mod p
	tv.Exp(&g, &r, &p)
	c.Exp(&y, &c, &p)
	tv.Mul(&tv, &c)
	tv.Mod(&tv, &p)

	// Check equality of t's
	if t.Cmp(&tv) != 0 {
		err = fmt.Errorf("WRONG! Calculated %v, received %v.", tv, t)
	}

	return
}

// t, r are the ZKP
func CheckDiscreteLogEqualityProof(G []big.Int, Y []big.Int, t []big.Int, r big.Int, p big.Int, q big.Int) (err error) {
	// Verification
	var tv, c, n big.Int

	c = computeCMany(G, Y, t, *Q)

	for i := 0; i < len(G); i++ {
		// Compute tv = g^r * y^c mod P
		tv.Exp(&G[i], &r, P)
		n.Exp(&Y[i], &c, P)
		tv.Mul(&tv, &n)
		tv.Mod(&tv, P)

		// So what do we have here?
		if t[i].Cmp(&tv) != 0 {
			// Record all the errors, not just the first or last (for testing purposes)
			err2 := fmt.Errorf("WRONG! Calculated %v, received %v.", tv, t[i])
			if err != nil {
				err = fmt.Errorf("%v\n%v", err, err2)
			} else {
				err = err2
			}
		}
	}

	return
}
