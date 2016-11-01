package zkp

import (
	"math/big"
	"testing"
)

// TODO CHECK INCORRECT VALUES ANUNAY YOU FUCK

func TestDiscreteLogKnowledge(test *testing.T) {
	for i := 0; i < NumTests; i++ {
		var x, y big.Int

		g := GenerateG(P, Q)

		// Generate private key, public key pair
		x.Rand(RandGen, Q) // x = rand() mod Q // TODO also shouldn't be 0
		y.Exp(&g, &x, P)   // y = g^x mod P

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
		x.Rand(RandGen, Q)

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
		x.Rand(RandGen, Q) // x = rand() mod Q
		y.Exp(&g, &x, P)   // y = g^x mod P
		r.Rand(RandGen, Q) // r = rand() mod Q

		// Test case 1: m = 1 and z = 42 returns TRUE
		m = *One
		z = *FortyTwo

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
		m = *FortyTwo
		z = *FortyTwo

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
