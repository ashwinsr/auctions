package zkp

import (
	"math/big"
	"math/rand"
)

func EncryptElGamal(m *big.Int, r *big.Int, y *big.Int, p *big.Int, q *big.Int, g *big.Int) (c Ciphertext) {
	var temp big.Int

	temp.Exp(y, r, p)

	c.Alpha.Mul(m, &temp)
	c.Alpha.Mod(&c.Alpha, p)

	c.Beta.Exp(g, r, p)

	return
}

func DecryptElGamal(c Ciphertext, x *big.Int, p *big.Int) (m big.Int) {
	var temp big.Int

	temp.Exp(&c.Beta, x, p)
	temp.ModInverse(&temp, p)

	m.Mul(&temp, &c.Alpha)
	m.Mod(&m, p)

	return
}

func MultiplyElGamal(a Ciphertext, b Ciphertext, p *big.Int) (c Ciphertext) {
	c.Alpha.Mul(&a.Alpha, &b.Alpha)
	c.Alpha.Mod(&c.Alpha, p)

	c.Beta.Mul(&a.Beta, &b.Beta)
	c.Beta.Mod(&c.Beta, p)

	return
}

func makeRandPerm(n int) Permutation {
	perm := rand.Perm(n)
	var revperm []int
	revperm = make([]int, n)

	for i := 0; i < n; i++ {
		revperm[perm[i]] = i
	}
	return Permutation{Forward: perm, Backward: revperm}
}

func RandomlyPermute(e []Ciphertext, p big.Int, q big.Int, g big.Int, y big.Int) (
	E []Ciphertext,
	c []big.Int, cd big.Int, cD big.Int, ER Ciphertext,
	f []big.Int, fd big.Int, yd big.Int, zd big.Int, F []big.Int,
	yD big.Int, zD big.Int, Z big.Int) {

	pi := makeRandPerm(len(e))

	var R []big.Int

	for j := 0; j < len(e); j++ {
		var r big.Int
		r.Rand(RandGen, &q)
		cOne := EncryptElGamal(One, &r, &y, &p, &q, &g)
		c := MultiplyElGamal(e[pi.Forward[j]], cOne, &p)
		E = append(E, c)
		R = append(R, r)
	}

	c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z = VerifiableSecretShuffle(e, E, y, g, *P, *Q, pi, R)

	return
}

func CipherTextsToAlphasBetas(e []Ciphertext) (alphas []big.Int, betas []big.Int) {
	for _, c := range e {
		alphas = append(alphas, c.Alpha)
		betas = append(betas, c.Beta)
	}
	return
}

func AlphasBetasToCipherTexts(alphas []big.Int, betas []big.Int) (e []Ciphertext) {
	for i := 0; i < len(alphas); i++ {
		e = append(e, Ciphertext{Alpha: alphas[i], Beta: betas[i]})
	}
	return
}
