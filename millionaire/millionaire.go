package millionaire

import (
	"math/big"
	"log"
	"github.com/ashwinsr/auctions/zkp"
)

type PhiStruct struct {
	Phis []big.Int
}

type GammaDeltaStruct struct {
	Gammas, Deltas []big.Int
}

// Computes PI_{d=j+1}^{k} (a1_d/a2_d)^2^d-2
// where a1 and a2 are either both alpha arrays
// or beta
func multiplyDivideExponentiate(a1 []big.Int, a2 []big.Int, j int, p big.Int) big.Int {
	product := *big.NewInt(1)
	var temp, tempExp big.Int

	for d := j + 1; uint(d) < zkp.K_Mill; d++ {
		temp.ModInverse(&a2[d], &p)
		temp.Mul(&a1[d], &temp)

		// because d is considered an array index, when used for the actual math,
		// we must add 1 to it
		tempD := big.NewInt(int64(d + 1))
		tempExp.Exp(zkp.Two, tempD, nil)
		tempExp.Sub(&tempExp, zkp.Two)
		// tempExp.Mod(&tempExp, &p)

		temp.Exp(&temp, &tempExp, &p)

		product.Mul(&product, &temp)
		product.Mod(&product, &p)
	}

	return product
}

// Whoever calls this function: make sure you understand what bigY means.
func MillionaireCalculateGammaDelta(alpha_1 []big.Int, alpha_2 []big.Int,
	beta_1 []big.Int, beta_2 []big.Int, bigY big.Int, p big.Int) *GammaDeltaStruct {
	var gds GammaDeltaStruct

	for j := 0; uint(j) < zkp.K_Mill; j++ {
		var gammaJ, deltaJ big.Int
		var temp, temp2, temp3, temp4 big.Int

		// Compute gammaJ = Y*alpha_2j / alpha_1j
		temp.ModInverse(&alpha_1[j], &p)
		temp.Mul(&alpha_2[j], &temp)
		temp.Mul(&temp, &bigY)
		gammaJ.Mod(&temp, &p)

		// Compute gammaJ = gammaJ * multipleDivideExponentiate
		temp2 = multiplyDivideExponentiate(alpha_1, alpha_2, j, p)
		gammaJ.Mul(&temp2, &gammaJ)
		gammaJ.Mod(&gammaJ, &p)

		// Compute deltaJ = beta_2j/beta_1j
		temp3.ModInverse(&beta_1[j], &p)
		temp3.Mul(&beta_2[j], &temp3)
		deltaJ.Mod(&temp3, &p)

		// Compute deltaJ = deltaJ * multiplyDivideExponentiate
		temp4 = multiplyDivideExponentiate(beta_1, beta_2, j, p)
		deltaJ.Mul(&temp4, &deltaJ)
		deltaJ.Mod(&deltaJ, &p)

		log.Printf("At j=%v, gamma = %v and delta = %v\n", j, gammaJ, deltaJ)

		gds.Gammas = append(gds.Gammas, gammaJ)
		gds.Deltas = append(gds.Deltas, deltaJ)
	}

	return &gds
}

func MillionaireCalculateV(gamma1 big.Int, gamma2 big.Int, phi1 big.Int, phi2 big.Int, p big.Int) big.Int {
	var temp1, temp2, v big.Int

	// Calculate gamma1 * gamma2 mod p
	temp1.Mul(&gamma1, &gamma2)
	temp1.Mod(&temp1, &p)

	// Calculate 1/(phi1 * phi2) mod p
	temp2.Mul(&phi1, &phi2)
	temp2.Mod(&temp2, &p)
	temp2.ModInverse(&temp2, &p)

	// Calculate v
	v.Mul(&temp1, &temp2)
	v.Mod(&v, &p)

	return v
}
