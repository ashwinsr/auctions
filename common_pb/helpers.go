package common_pb

import "math/big"

func CreateIsOneOfTwo(a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2 big.Int) *EqualsOneOfTwo {
	return &EqualsOneOfTwo{
		A_1: a_1.Bytes(),
		A_2: a_2.Bytes(),
		B_1: b_1.Bytes(),
		B_2: b_2.Bytes(),
		D_1: d_1.Bytes(),
		D_2: d_2.Bytes(),
		R_1: r_1.Bytes(),
		R_2: r_2.Bytes(),
	}
}

func DestructIsOneOfTwo(proof *EqualsOneOfTwo) (a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2 big.Int) {
	a_1.SetBytes(proof.A_1)
	a_2.SetBytes(proof.A_2)
	b_1.SetBytes(proof.B_1)
	b_2.SetBytes(proof.B_2)
	d_1.SetBytes(proof.D_1)
	d_2.SetBytes(proof.D_2)
	r_1.SetBytes(proof.R_1)
	r_2.SetBytes(proof.R_2)
	return
}

func CreateDiscreteLogKnowledge(t, r big.Int) *DiscreteLogKnowledge {
	return &DiscreteLogKnowledge{T: t.Bytes(), R: r.Bytes()}
}

func DestructDiscreteLogKnowledge(proof *DiscreteLogKnowledge) (t, r big.Int) {
	t.SetBytes(proof.T)
	r.SetBytes(proof.R)
	return
}

func CreateDiscreteLogEquality(ts []big.Int, r big.Int) *DiscreteLogEquality {
	var logEqualityProof DiscreteLogEquality
	for _, t := range ts {
		logEqualityProof.Ts = append(logEqualityProof.Ts, t.Bytes())
	}
	logEqualityProof.R = r.Bytes()

	return &logEqualityProof
}

func DestructDiscreteLogEquality(proof *DiscreteLogEquality) (ts []big.Int, r big.Int) {
	r.SetBytes(proof.R)
	for _, t := range proof.Ts {
		var t_temp big.Int
		t_temp.SetBytes(t)
		ts = append(ts, t_temp)
	}
	return
}

func BigIntSliceToByteSlice(ints []big.Int) (res [][]byte) {
	for _, num := range ints {
		res = append(res, num.Bytes())
	}
	return
}

func ByteSliceToBigIntSlice(ints [][]byte) (res []big.Int) {
	for _, num := range ints {
		res = append(res, *new(big.Int).SetBytes(num))
	}
	return
}
