package zkp

import (
	"math/big"
	"testing"
)

func TestDiscreteLogKnowledge(test *testing.T) {
	for i := 0; i < NumTests; i++ {
		var x, y big.Int

		g := GenerateG(P, Q)
		// test.Logf("g = %v", g)

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
