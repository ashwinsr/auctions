package main

import (
	   "math/big"
	   "github.com/ashwinsr/auctions/zkp"
)

type GammaDeltaStruct struct {
	 gammas, deltas []big.Int
}

// Computes PI_{d=j+1}^{k} (a1_d/a2_d)^2^d-2
// where a1 and a2 are either both alpha arrays
// or beta 
func multiplyDivideExponentiate(a1 []big.Int, a2 []big.Int, j int, p big.Int) big.Int {
	 product := *big.NewInt(1)
	 var temp, tempExp big.Int

	 for d := j+1; uint(d) < zkp.K_Mill; d++ {
	 	 temp.ModInverse(&a2[d], &p)
		 temp.Mul(&a1[d], &temp)
		 
		 tempD := *big.NewInt(int64(d))
		 tempExp.Exp(zkp.Two, &tempD, &p)
		 tempExp.Sub(&tempExp, zkp.Two)
		 tempExp.Mod(&tempExp, &p)

		 temp.Exp(&temp, &tempExp, &p)

		 product.Mul(&product, &temp)
		 product.Mod(&product, &p)
	 }

	 return product
}

// Whoever calls this function: make sure you understand what bigY means.
func millionaireCalculateGammaDelta(alpha_1 []big.Int, alpha_2 []big.Int,
	 								beta_1 []big.Int, beta_2 []big.Int, bigY big.Int, p big.Int) *GammaDeltaStruct {
	 var gds GammaDeltaStruct
	 var gammaJ, deltaJ big.Int
	 var temp big.Int

	 for j := 0; uint(j) < zkp.K_Mill; j++ {
	 	 // Compute gammaJ = Y*alpha_2j / alpha_1j
		 temp.ModInverse(&alpha_1[j], &p)
         temp.Mul(&alpha_2[j], &temp)
		 temp.Mul(&temp, &bigY)
		 gammaJ.Mod(&temp, &p)
		 
		 // Compute gammaJ = gammaJ * multipleDivideExponentiate
		 temp = multiplyDivideExponentiate(alpha_1, alpha_2, j, p)
	 	 gammaJ.Mul(&temp, &gammaJ)
		 gammaJ.Mod(&gammaJ, &p)

		 // Compute deltaJ = beta_2j/beta_1j
		 temp.ModInverse(&beta_1[j], &p)
         temp.Mul(&beta_2[j], &temp)
         deltaJ.Mod(&temp, &p)

		 // Compute deltaJ = deltaJ * multiplyDivideExponentiate
		 temp = multiplyDivideExponentiate(beta_1, beta_2, j, p)
		 deltaJ.Mul(&temp, &deltaJ)
		 deltaJ.Mod(&deltaJ, &p)

	 	 gds.gammas = append(gds.gammas, gammaJ)
		 gds.deltas = append(gds.deltas, deltaJ)
	 }

	 return &gds
}