package zkp

import (
	// "fmt"
	"math/big"
)

func EncryptElGamal(m *big.Int, y *big.Int, p *big.Int, q *big.Int, g *big.Int) (c Ciphertext) {
	var temp, r big.Int

	r.Rand(RandGen, q)

	temp.Exp(y, &r, p)

	c.Alpha.Mul(m, &temp)
	c.Alpha.Mod(&c.Alpha, p)

	c.Beta.Exp(g, &r, p)

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
