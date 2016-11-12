package zkp

import (
	"math/big"
	"math/rand"
	"testing"
)

// func ReEncryptElGamal(alpha big.Int, beta big.Int, R big.Int y big.Int) (alpha big.Int, beta big.Int) {
// 	var alphaZero, betaZero big.Int
  
// }

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

func makeRandPerm(n int) (Permutation) {
 	perm := rand.Perm(n)
 	var revperm []int
 	for i := 0; i < n; i++ {
 		revperm[perm[i]] = i
 	}
 	return Permutation{forward: perm, backward: revperm}
 } 

// func TestVerifiableSecretShuffle(test *testing.T) {

// 	var RegularCiphertexts = []Ciphertext { 
//  	   Ciphertext {
// 	        alpha: *One, 
// 	        beta: *FortyTwo, 
// 	    },
// 	    Ciphertext {
// 	        alpha: *One, 
// 	        beta: *One, 
// 	    },
// 	}
// 	var ShuffledCiphertexts = []Ciphertext { 
//  	   Ciphertext {
// 	        alpha: *One, 
// 	        beta: *One, 
// 	    },
// 	    Ciphertext {
// 	        alpha: *One, 
// 	        beta: *FortyTwo, 
// 	    },
// 	}

// 	g := GenerateG(P, Q)
// 	pi := makeRandPerm(len(e))

// 	c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z := VerifiableSecretShuffle(RegularCiphertexts, ShuffledCiphertexts, *One, g, *P, *Q, pi, R []big.Int)	
	
// 	err := CheckVerifiableSecretShuffle(c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z)


// }
