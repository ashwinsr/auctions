package zkp

import (
	"crypto/sha256"
	"fmt"
	"log"
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
	if len(g) < 2 {
		log.Fatalf("Passed not enough bases to DiscreteLogEquality!\n")
	}

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
	beta.Exp(&g, &r, &p)  // beta = g^r mod p

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

func VerifiableSecretShuffle(e []Ciphertext, E []Ciphertext, y big.Int, g big.Int, p big.Int, q big.Int, pi Permutation, R []big.Int) (c []big.Int, cd big.Int, cD big.Int, ER Ciphertext, f []big.Int, fd big.Int, yd big.Int, zd big.Int, F []big.Int, yD big.Int, zD big.Int, Z big.Int) {
	var rd, rD, sd, sD, delta, RR big.Int
	var n int
	n = len(e)

	var d, r, D []big.Int
	d = make([]big.Int, n)
	r = make([]big.Int, n)
	D = make([]big.Int, n)
	c = make([]big.Int, n)

	for i := 0; i < n; i++ {
		d[i].Mul(Lt, Ls)
		d[i].Rand(RandGen, &d[i])
		r[i].Rand(RandGen, &q)
		D[i].Rand(RandGen, &q)
	}

	rd.Rand(RandGen, &q)
	rD.Rand(RandGen, &q)
	sd.Rand(RandGen, &q)
	sD.Rand(RandGen, &q)

	delta.Rand(RandGen, &q)

	RR.Rand(RandGen, &q) // TODO: Look at this later

	ER.Alpha.Exp(&y, &RR, &p) // This is the encryption E(1; R_R)
	ER.Beta.Exp(&g, &RR, &p)

	SumDICubed := Zero

	cd_commitment_array := make([]big.Int, n+2)
	cD_commitment_array := make([]big.Int, n+2)

	for i := 0; i < n; i++ {
		var temp big.Int
		temp.Exp(&E[i].Alpha, &D[i], &p)
		ER.Alpha.Mul(&ER.Alpha, &temp)
		ER.Alpha.Mod(&ER.Alpha, &p)

		temp.Exp(&E[i].Beta, &D[i], &p)
		ER.Beta.Mul(&ER.Beta, &temp)
		ER.Alpha.Mod(&ER.Alpha, &p)

		c_i := make([]big.Int, n+2) // TODO: put this outside the for loop

		// Begin setting up of c_i's
		inverse := pi.Backward[i]

		c_i[inverse] = *One

		c_i[n].Mul(Three, &d[inverse])
		c_i[n].Mod(&c_i[n], &p)

		c_i[n+1].Mul(&c_i[n], &d[inverse])
		c_i[n+1].Mod(&c_i[n+1], &p)

		c[i] = CreateCommitment(c_i, r[i])
		// Done makeing c_i's

		// Assigning d_i and D_i to c_d and c_D respectiveky
		cd_commitment_array[i] = d[i]
		cD_commitment_array[i] = D[i]

		// Finding sum of d_j^3, which is a term in c_d
		var dICubed big.Int
		dICubed.Mul(&d[i], &d[i])
		dICubed.Mul(&dICubed, &d[i])
		dICubed.Mod(&dICubed, &p)
		SumDICubed.Add(SumDICubed, &dICubed)
	}

	cd_commitment_array[n] = sd
	cD_commitment_array[n] = delta

	cd_commitment_array[n+1].Sub(SumDICubed, &delta)
	cd_commitment_array[n+1].Mod(&cd_commitment_array[n+1], &p) // Storing Sum((d_j)^3) - delta

	cD_commitment_array[n+1] = sD

	cd = CreateCommitment(cd_commitment_array, rd)
	cD = CreateCommitment(cD_commitment_array, rD)

	// Done doing the initial stage

	// Computing t_1, ... , t_n challenge for Fiat-Shamir approach
	h := sha256.New()

	var t []big.Int
	t = make([]big.Int, n)
	f = make([]big.Int, n)
	F = make([]big.Int, n)

	fd = *Zero
	yd = *Zero
	yD = *Zero
	zd = *Zero
	zD = *Zero
	Z = *Zero

	for i := 0; i < n; i++ {
		h.Write(c[i].Bytes()[:])
		t[i].SetBytes(h.Sum(nil))
		t[i].Mod(&t[i], Lt) // Storing t_i as a random value less than Lt
		h.Reset()

		// Setting f_j = t_(pi(j)) + d_j
		f[i].Add(&t[pi.Forward[i]], &d[i])
		f[i].Mod(&f[i], &q) // TODO: figure out modulo factor

		// Setting F_j = (t_(pi(j)))^2 + D_j
		tj_squared := t[pi.Forward[i]]
		tj_squared.Exp(&tj_squared, big.NewInt(2), &q) // TODO: figure out modulo factor
		F[i].Add(&tj_squared, &D[i])
		F[i].Mod(&F[i], &q) // TODO: figure out modulo factor

		var part_fd, part_yd, part_yD, part_zd, part_zD big.Int

		inverse := pi.Backward[i]

		part_fd.Mul(&d[inverse], &t[i])
		part_fd.Mul(&d[inverse], &part_fd)
		fd.Add(&fd, &part_fd)
		fd.Mod(&fd, &q) // TODO: check modulo

		part_yd.Mul(&d[inverse], &t[i])
		yd.Add(&yd, &part_yd)
		yd.Mod(&yd, &q) // TODO: check modulo

		part_yD.Mul(&d[inverse], &t[i])
		part_yD.Mul(&part_yD, &part_yD)
		yD.Add(&yD, &part_yD)
		yD.Mod(&yD, &q) // TODO: check modulo

		part_zd.Mul(&r[i], &t[i])
		zd.Add(&zd, &part_zd)
		zd.Mod(&zd, &q) // TODO: check modulo

		part_zD.Mul(&r[i], &t[i])
		part_zD.Mul(&part_zD, &t[i])
		zD.Add(&zD, &part_zD)
		zD.Mod(&zD, &q) // TODO: check modulo

	}

	fd.Mul(Three, &fd)
	fd.Add(&fd, &cd_commitment_array[n+1])

	yd.Mul(Three, &yd)
	yd.Add(&yd, &cd_commitment_array[n])

	yD.Mul(Three, &yD)
	yD.Add(&yD, &cD_commitment_array[n+1])

	zd.Add(&zd, &rd)
	zD.Add(&zD, &rD)

	// Modulo of all these things above TODO

	// Need to do this seperately because this uses pi(i) to access elements of t
	for i := 0; i < n; i++ {
		var part_Z big.Int

		part_Z.Mul(&t[pi.Forward[i]], &R[i])
		Z.Add(&Z, &part_Z)
		Z.Mod(&Z, &q) // TODO: check modulo
	}

	Z.Add(&Z, &RR)

	return
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
			if h.Cmp(One) != 0 && h.Cmp(Zero) != 0 { // TODO: Should not be 0, right?
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
	if len(G) < 2 {
		log.Fatalf("Passed not enough bases to CheckDiscreteLogEqualityProof!\n")
	}

	if len(Y) < 2 {
		log.Fatalf("Passed not enough results to CheckDiscreteLogEqualityProof!\n")
	}

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
	}

	// Check a_1 = g^r_1 * beta^d_1
	temp_1.Exp(&beta, &d_1, &p)
	temp_2.Exp(&g, &r_1, &p)
	temp_1.Mul(&temp_1, &temp_2)
	temp_1.Mod(&temp_1, &p)
	if temp_1.Cmp(&a_1) != 0 {
		err = fmt.Errorf("2 - WRONG! Calculated %v, received %v.\n", temp_1, a_1)
	}

	// Check a_2 = g^r_2 * beta^d_2
	temp_1.Exp(&beta, &d_2, &p)
	temp_2.Exp(&g, &r_2, &p)
	temp_1.Mul(&temp_1, &temp_2)
	temp_1.Mod(&temp_1, &p)
	if temp_1.Cmp(&a_2) != 0 {
		err = fmt.Errorf("3 - WRONG! Calculated %v, received %v.\n", temp_1, a_2)
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
	}

	// Check b_2 = y^r_2 * alpha^d_2
	temp_1.Exp(&y, &r_2, &p)
	temp_2.Exp(&alpha, &d_2, &p)
	temp_1.Mul(&temp_1, &temp_2)
	temp_1.Mod(&temp_1, &p)
	if temp_1.Cmp(&b_2) != 0 {
		err = fmt.Errorf("5 - WRONG! Calculated %v, received %v.\n", temp_1, b_2)
	}

	return
}

func CheckVerifiableSecretShuffle(e []Ciphertext, E []Ciphertext, p big.Int, q big.Int, g big.Int, y big.Int, c []big.Int, cd big.Int, cD big.Int, ER Ciphertext, f []big.Int, fd big.Int, yd big.Int, zd big.Int, F []big.Int, yD big.Int, zD big.Int, Z big.Int) (err error) {

	h := sha256.New()
	n := len(e)
	t := make([]big.Int, n)

	var fD big.Int
	fD = *Zero

	RHS1_commitment_array := make([]big.Int, n+2)
	RHS2_commitment_array := make([]big.Int, n+2)
	// var RHS3 Ciphertext
	LHS1 := cd
	LHS2 := cD
	LHS3 := Ciphertext{Alpha: *One, Beta: *One}
	RHS3 := Ciphertext{Alpha: *One, Beta: *One}

	for i := 0; i < n; i++ {
		h.Write(c[i].Bytes()[:])
		t[i].SetBytes(h.Sum(nil))
		t[i].Mod(&t[i], Lt) // Storing t_i as a random value less than Lt
		h.Reset()

		var ct big.Int
		ct.Exp(&c[i], &t[i], nil)
		LHS1.Mul(&LHS1, &ct)
		// LHS1.Mod(&LHS1, ) This needs to be figured out TODO

		ct.Mul(&t[i], &t[i])
		ct.Exp(&c[i], &ct, nil) // Modulo issues

		LHS2.Mul(&LHS2, &ct)
		// LHS2.Mod(LHS2, ) This needs to be figured out TODO

		var Ef Ciphertext
		Ef.Alpha.Mul(&E[i].Alpha, &f[i])
		Ef.Beta.Mul(&E[i].Beta, &f[i])
		LHS3.Alpha.Mul(&LHS3.Alpha, &Ef.Alpha)
		LHS3.Beta.Mul(&LHS3.Beta, &Ef.Beta)
		LHS3.Alpha.Mod(&LHS3.Alpha, P) // Modulo needs to be figured
		LHS3.Beta.Mod(&LHS3.Beta, P)   // Modulo needs to be figured

		RHS1_commitment_array[i] = f[i]
		RHS2_commitment_array[i] = F[i]

		var et Ciphertext
		et.Alpha.Mul(&e[i].Alpha, &t[i])
		et.Beta.Mul(&e[i].Beta, &t[i])

		RHS3.Alpha.Mul(&RHS3.Alpha, &et.Alpha)
		RHS3.Beta.Mul(&RHS3.Beta, &et.Beta)

		var temp big.Int

		temp.Exp(&f[i], Three, nil)
		fD.Add(&fD, &temp)
		temp.Exp(&t[i], Three, nil)
		fD.Sub(&fD, &temp)
	}
	fD.Sub(&fD, &fd)

	var RHS3_part Ciphertext

	RHS3_part = EncryptElGamal(One, &Z, &y, P, Q, &g)
	// fmt.Println(RHS3.Alpha)
	// fmt.Println(RHS3.Beta)

	// RHS3_part.Alpha.Exp(&y, &Z, &p) // This is the encryption E(1; R_R)
	// RHS3_part.Beta.Exp(&g, &Z, &p)

	RHS3.Alpha.Mul(&RHS3.Alpha, &RHS3_part.Alpha)
	RHS3.Beta.Mul(&RHS3.Beta, &RHS3_part.Beta)

	RHS3.Alpha.Mod(&RHS3.Alpha, P) // TODO Modulo
	RHS3.Beta.Mod(&RHS3.Beta, P)   // TODO Modulo

	RHS1_commitment_array[n] = yd
	RHS2_commitment_array[n] = fD

	RHS1_commitment_array[n+1] = fd
	RHS2_commitment_array[n+1] = yD

	RHS1 := CreateCommitment(RHS1_commitment_array, zd)
	RHS2 := CreateCommitment(RHS2_commitment_array, zD)

	if LHS1.Cmp(&RHS1) != 0 {
		err = fmt.Errorf("Verifiable Random Shuffle Step 1 WRONG! LHS %v, RHS %v.\n", LHS1, RHS1)
		fmt.Println("LHS1 != RHS1")
	}

	if LHS2.Cmp(&RHS2) != 0 {
		err = fmt.Errorf("Verifiable Random Shuffle Step 2 WRONG! LHS %v, RHS %v.\n", LHS2, RHS2)
		fmt.Println("LHS2 != RHS2")
	}

	if LHS3.Alpha.Cmp(&RHS3.Alpha) != 0 {
		fmt.Println("LHS3.Alpha != RHS3.Alpha")
		fmt.Println(LHS3.Alpha.String())
		fmt.Println(RHS3.Alpha.String())
	}

	if LHS3.Beta.Cmp(&RHS3.Beta) != 0 {
		fmt.Println("LHS3.Beta != RHS3.Beta")
		fmt.Println(LHS3.Beta.String())
		fmt.Println(RHS3.Beta.String())
	}

	if LHS3.Alpha.Cmp(&RHS3.Alpha) != 0 || LHS3.Beta.Cmp(&RHS3.Beta) != 0 {
		err = fmt.Errorf("Verifiable Random Shuffle Step 3 WRONG! LHS %v, RHS %v.\n", LHS3.Alpha, RHS3.Alpha)
		return
	}

	return
}
