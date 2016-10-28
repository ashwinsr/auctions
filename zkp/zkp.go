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

func ComputeCSingle(g big.Int, y big.Int, t big.Int, q big.Int) (c big.Int) {
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
	c = ComputeCSingle(g, y, t, q)

	// Calculate r = v - cx
	A.Mul(&c, &x) // A = c * x
	r.Sub(&v, &A) // r = v - c*x
	r.Mod(&r, &q) // r = r mod q

	return t, r
}

func ComputeCMany(g []big.Int, Y []big.Int, t []big.Int, q big.Int) (c big.Int) {
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
	c = ComputeCMany(g, Y, t, q)

	// Calculate r = v - cx mod q
	A.Mul(&c, &x) // A = c*x
	r.Sub(&v, &A) // r = v - c*x
	r.Mod(&r, &q) // r = r mod q

	return t, r
}

// Generates a zero knowledge proof that guarantees that an El-gamal
// encrypted value (alpha, beta) = (my^r, g^r) decrypts to either 1 or a z in G_q.
func EncryptedValueIsOneOfTwo(m big.Int, y big.Int, r big.Int, g big.Int, z big.Int,
	p big.Int, q big.Int) (big.Int, big.Int, big.Int, big.Int, big.Int, big.Int, big.Int, big.Int) {
	var r_1, r_2, d_1, d_2, w, temp_1, temp_2 big.Int
	var alpha, beta big.Int
	var a_1, a_2, b_1, b_2, c big.Int

	// Compute alpha and beta
	temp_1.Exp(&y, &r, &p)
	alpha.Mul(&temp_1, &m)
	alpha.Mod(&alpha, &p) // alpha = m*y^r mod p
	beta.Exp(&g, &r, &p)  // beta = g^r mod p     <- should this be mod q?????/

	r_1.Rand(RandGen, &q)
	r_2.Rand(RandGen, &q)
	d_1.Rand(RandGen, &q)
	d_2.Rand(RandGen, &q)
	w.Rand(RandGen, &q)

	// If message is one
	if m.Cmp(One) == 0 {
		// Compute a_1 = g^r_1*beta^d_1 mod p
		temp_1.Exp(&beta, &d_1, &p)
		temp_2.Exp(&g, &r_1, &p)
		a_1.Mul(&temp_1, &temp_2)
		a_1.Mod(&a_1, &p)

		// Compute a_2 = g^w mod p
		a_2.Exp(&g, &w, &p)

		// Compute b_1 = y^r_1*(alpha/z)^d_1 mod p
		temp_1.Exp(&y, &r_1, &p)
		temp_2.ModInverse(&z, &p)
		temp_2.Mul(&temp_2, &alpha)
		temp_2.Exp(&temp_2, &d_1, &p)
		b_1.Mul(&temp_1, &temp_2)
		b_1.Mod(&b_1, &p)

		// Compute b_2 = y^w mod p
		b_2.Exp(&y, &w, &p)
	}

	// If message is z
	if m.Cmp(&z) == 0 {
		// Compute a_1 = g^w mod p
		a_1.Exp(&g, &w, &p)

		// Compute a_2 = g^r_2*beta^d_2 mod p
		temp_1.Exp(&beta, &d_2, &p)
		temp_2.Exp(&g, &r_2, &p)
		a_2.Mul(&temp_1, &temp_2)
		a_2.Mod(&a_2, &p)

		// Compute b_1 = y^w mod p
		b_1.Exp(&y, &w, &p)

		// Compute b_2 = y^r_2*alpa^d_2 mod p
		temp_1.Exp(&y, &r_2, &p)
		temp_2.Exp(&alpha, &d_2, &p)
		b_2.Mul(&temp_1, &temp_2)
		b_2.Mod(&b_2, &p)
	}

	// Compute c
	h := sha256.New()

	// Compute c = SHA256(a_1, a_2, b_1, b_2) mod q
	h.Write(a_1.Bytes()[:])
	h.Write(a_2.Bytes()[:])
	h.Write(b_1.Bytes()[:])
	h.Write(b_2.Bytes()[:])
	c.SetBytes(h.Sum(nil))
	c.Mod(&c, &q)

	// If message is one
	if m.Cmp(One) == 0 {
		// d_2 = c - d1 mod q
		d_2.Sub(&c, &d_1)
		d_2.Mod(&d_2, &q)

		// r_2 = w - r*d_2 mod q
		r_2.Mul(&r, &d_2)
		r_2.Mod(&r_2, &q)
		r_2.Sub(&w, &r_2)
		r_2.Mod(&r_2, &q)
	}

	// If message is z
	if m.Cmp(&z) == 0 {
		// d_1 = c - d_2 mod q
		d_1.Sub(&c, &d_2)
		d_1.Mod(&d_1, &q)

		// r_1 = w - r*d_1 mod q
		r_1.Mul(&r, &d_1)
		r_1.Mod(&r_1, &q)
		r_1.Sub(&w, &r_1)
		r_1.Mod(&r_1, &q)
	}

	return a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2
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

	c := ComputeCSingle(g, y, t, q)

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

	c = ComputeCMany(G, Y, t, *Q)

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

func CheckEncryptedValueIsOneOfTwo(alpha big.Int, beta big.Int,
	p big.Int, q big.Int,
	a_1 big.Int, a_2 big.Int,
	b_1 big.Int, b_2 big.Int,
	d_1 big.Int, d_2 big.Int,
	r_1 big.Int, r_2 big.Int,
	g big.Int, y big.Int, z big.Int) (err error) {
	var c, temp_1, temp_2 big.Int

	// Compute c = SHA256(a_1, a_2, b_1, b_2) mod q
	h := sha256.New()
	h.Write(a_1.Bytes()[:])
	h.Write(a_2.Bytes()[:])
	h.Write(b_1.Bytes()[:])
	h.Write(b_2.Bytes()[:])
	c.SetBytes(h.Sum(nil))
	c.Mod(&c, &q) // c = c mod q

	// Check c = d_1 + d_2 mod q
	temp_1.Add(&d_1, &d_2)
	temp_1.Mod(&temp_1, &q)
	if temp_1.Cmp(&c) != 0 {
		err = fmt.Errorf("1 - WRONG! Calculated %v, received %v.\n", temp_1, c)
		fmt.Println("1")
	}

	// Check a_1 = g^r_1 * beta^d_1
	temp_1.Exp(&beta, &d_1, &p)
	temp_2.Exp(&g, &r_1, &p)
	temp_1.Mul(&temp_1, &temp_2)
	temp_1.Mod(&temp_1, &p)
	if temp_1.Cmp(&a_1) != 0 {
		err = fmt.Errorf("2 - WRONG! Calculated %v, received %v.\n", temp_1, a_1)
		fmt.Println("2")
	}

	// Check a_2 = g^r_2 * beta^d_2
	temp_1.Exp(&beta, &d_2, &p)
	temp_2.Exp(&g, &r_2, &p)
	temp_1.Mul(&temp_1, &temp_2)
	temp_1.Mod(&temp_1, &p)
	if temp_1.Cmp(&a_2) != 0 {
		err = fmt.Errorf("3 - WRONG! Calculated %v, received %v.\n", temp_1, a_2)
		fmt.Println("3")
	}

	// Check b_1 = y^r_1 * (alpha/z)^d_1
	temp_1.Exp(&y, &r_1, &p)
	temp_2.ModInverse(&z, &p)
	temp_2.Mul(&temp_2, &alpha)
	temp_2.Exp(&temp_2, &d_1, &p)
	temp_1.Mul(&temp_1, &temp_2)
	temp_1.Mod(&temp_1, &p)
	if temp_1.Cmp(&b_1) != 0 {
		err = fmt.Errorf("4 - WRONG! Calculated %v, received %v.\n", temp_1, b_1)
		fmt.Println("4")
	}

	// Check b_2 = y^r_2 * alpha^d_2
	temp_1.Exp(&y, &r_2, &p)
	temp_2.Exp(&alpha, &d_2, &p)
	temp_1.Mul(&temp_1, &temp_2)
	temp_1.Mod(&temp_1, &p)
	if temp_1.Cmp(&b_2) != 0 {
		err = fmt.Errorf("5 - WRONG! Calculated %v, received %v.\n", temp_1, b_2)
		fmt.Println("5")
	}

	return
}
