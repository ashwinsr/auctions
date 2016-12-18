package zkp

import (
	// "fmt"
	"math/big"
	"testing"
)

// FIXME test soundness as well, not just completeness

func TestDiscreteLogKnowledge(test *testing.T) {
	for i := 0; i < NumTests; i++ {
		var x, y big.Int

		g := GenerateG(P, Q)

		// Generate private key, public key pair
		x.Rand(RandGen, new(big.Int).Sub(Q, One))
		x.Add(&x, One)   // x is in [1, ..., Q]
		y.Exp(&g, &x, P) // y = g^x mod P

		// Generate zero-knowledge proof
		t, r := DiscreteLogKnowledge(x, g, *P, *Q)

		err := CheckDiscreteLogKnowledgeProof(g, y, t, r, *P, *Q)

		if err != nil {
			test.Error(err)
		}
	}
}

func TestDiscreteLogEquality(test *testing.T) {
	for i := 0; i < NumTests; i++ {

		// Generate private key
		var x big.Int
		x.Rand(RandGen, new(big.Int).Sub(Q, One))
		x.Add(&x, One) // x is in [1, ..., Q]

		G := GenerateGs(P, Q, 10)

		// Compute c
		Y := make([]big.Int, len(G))
		for i := 0; i < len(G); i++ {
			Y[i].Exp(&G[i], &x, P)
		}

		// Generate zero-knowledge proof
		t, r := DiscreteLogEquality(x, G, *P, *Q)

		err := CheckDiscreteLogEqualityProof(G, Y, t, r, *P, *Q)

		if err != nil {
			test.Error(err)
		}
	}
}

func TestEncryptedValueIsOneOfTwo(test *testing.T) {
	for i := 0; i < NumTests; i++ {
		var x, y, r big.Int
		var alpha, beta big.Int
		var m, z big.Int

		// Generate public/private key pairs
		g := GenerateG(P, Q)
		x.Rand(RandGen, new(big.Int).Sub(Q, One))
		x.Add(&x, One)     // x is in [1, ..., Q]
		y.Exp(&g, &x, P)   // y = g^x mod P
		r.Rand(RandGen, Q) // r = rand() mod Q

		// Test case 1: m = 1 and z = 42 returns TRUE
		m.Set(One)
		z.Set(FortyTwo)

		alpha.Exp(&y, &r, P)
		alpha.Mul(&alpha, &m)
		alpha.Mod(&alpha, P) // alpha = m*y^r mod P
		beta.Exp(&g, &r, P)  // beta = g^r mod P

		// Generate and verify ZKP
		a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2 := EncryptedValueIsOneOfTwo(m, y, r, g, z, *P, *Q)
		err := CheckEncryptedValueIsOneOfTwo(alpha, beta, *P, *Q, a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2, g, y, z)
		if err != nil {
			test.Error(err)
		}

		// Test case 2: m = z = random value return TRUE
		m.Set(FortyTwo)
		z.Set(FortyTwo)

		alpha.Exp(&y, &r, P)
		alpha.Mul(&alpha, &m)
		alpha.Mod(&alpha, P) // alpha = m*y^r mod P
		beta.Exp(&g, &r, P)  // beta = g^r mod P

		// Generate and verify ZKP
		a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2 = EncryptedValueIsOneOfTwo(m, y, r, g, z, *P, *Q)
		err = CheckEncryptedValueIsOneOfTwo(alpha, beta, *P, *Q, a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2, g, y, z)
		if err != nil {
			test.Error(err)
		}
	}
}

func TestVerifiableSecretShuffle(test *testing.T) {
	for i := 0; i < NumTests*10; i++ {
		var e, E []Ciphertext
		var x, y, r, m big.Int
		var R []big.Int

		g := GenerateG(P, Q)

		// Generate private key, public key pair
		x.Rand(RandGen, new(big.Int).Sub(Q, One))
		x.Add(&x, One)   // x is in [1, ..., Q]
		y.Exp(&g, &x, P) // y = g^x mod P

		n := 100

		for j := 0; j < n; j++ {
			m.Rand(RandGen, P) // Some message
			r.Rand(RandGen, Q)
			c := EncryptElGamal(&m, &r, &y, P, Q, &g)
			e = append(e, c)
		}

		pi := makeRandPerm(n)

		for j := 0; j < n; j++ {
			r.Rand(RandGen, Q)
			cOne := EncryptElGamal(One, &r, &y, P, Q, &g)
			c := MultiplyElGamal(e[pi.Forward[j]], cOne, P)
			E = append(E, c)
			R = append(R, r)
		}

		c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z := VerifiableSecretShuffle(e, E, y, g, *P, *Q, pi, R)
		err := CheckVerifiableSecretShuffle(e, E, *P, *Q, g, y, c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z)

		if err != nil {
			test.Error(err)
		}
	}

	// G := GenerateGsCommitment(10)
	//
	// for i := 0; i < 10; i++ {
	//   fmt.Println(G[i].String())
	// }

	// var RegularCiphertexts = []Ciphertext{
	//   Ciphertext{
	//     alpha: *One,
	//     beta:  *FortyTwo,
	//   },
	//   Ciphertext{
	//     alpha: *One,
	//     beta:  *One,
	//   },
	// }
	// var ShuffledCiphertexts = []Ciphertext{
	//   Ciphertext{
	//     alpha: *One,
	//     beta:  *One,
	//   },
	//   Ciphertext{
	//     alpha: *One,
	//     beta:  *FortyTwo,
	//   },
	// }

	// g := GenerateG(P, Q)
	// pi := makeRandPerm(len(e))

	// c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z := VerifiableSecretShuffle(RegularCiphertexts, ShuffledCiphertexts, *One, g, *P, *Q, pi, R []big.Int)

	// err := CheckVerifiableSecretShuffle(e, E, p, q, g, y, c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z)

}
