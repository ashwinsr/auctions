package zkp

import (
	// "fmt"
	"math/big"
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
