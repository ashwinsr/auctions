package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"

	pb "github.com/ashwinsr/auctions/common_pb"
	"github.com/ashwinsr/auctions/lib"
	"github.com/ashwinsr/auctions/zkp"
	"github.com/golang/protobuf/proto"
)

type PhiStruct struct {
	Phis []big.Int
}

type GammaDeltaStruct struct {
	Gammas, Deltas []big.Int
}

type AlphaBetaStruct struct {
	alphas, betas []big.Int
}

// keeps state
type state struct {
	myPrivateKey big.Int
	myPublicKey  big.Int
	keys         []big.Int
	publicKey    big.Int
	currRound    int

	// TODO millionaire specific
	myAlphasBetas                 *AlphaBetaStruct
	theirAlphasBetas              *AlphaBetaStruct
	myGammasDeltas                *GammaDeltaStruct
	theirGammasDeltas             *GammaDeltaStruct
	myExponentiatedGammasDeltas   *GammaDeltaStruct
	theirExponentiatedGammasDelta *GammaDeltaStruct
	phisBeforeExponentiation      *PhiStruct
	myPhis                        *PhiStruct
	theirPhis                     *PhiStruct
}

func getState(state_ interface{}) (s *state) {
	s, ok := state_.(*state)
	if !ok {
		log.Fatalf("Failed to typecast state.\n")
	}

	return
}

var (
	myAddress = flag.String("address", "localhost:1234", "address")
	bid       = flag.Uint("bid", 0, "Amount of money")
	// id        = flag.Int("id", -1, "ID")
	id = new(int)
)

// ROUND 1 FUNCTIONS

// TODO delete comment
/*
 * 1. Generates a private/public key pair
 * 2. Generates zero-knowledge-proof of private key
 * 3. Publishes the public key with zero-knowledge proof of private key
 * 4. Puts our own public key in state.keys
 * 5. Receives n public keys from keyChan, puts them in state.keys
 * 6. Calculates the final public key, and stores into state.
 */
func computeRound1(state interface{}) proto.Message {
	s := getState(state)

	// Generate private key
	s.myPrivateKey.Rand(zkp.RandGen, zkp.Q)
	// Calculate public key
	s.myPublicKey.Exp(zkp.G, &s.myPrivateKey, zkp.P)

	// Generate zkp of private key
	t, r := zkp.DiscreteLogKnowledge(s.myPrivateKey, *zkp.G, *zkp.P, *zkp.Q)

	return &pb.Key{
		Key:   s.myPublicKey.Bytes(),
		Proof: pb.CreateDiscreteLogKnowledge(t, r),
	}
}

func checkRound1(state interface{}, result *pb.OuterStruct) (err error) {
	var key pb.Key

	err = proto.Unmarshal(result.Data, &key)
	if err != nil {
		fmt.Println(err)
		log.Fatalf("Failed to unmarshal pb.Key.\n")
	}

	var k big.Int
	k.SetBytes(key.Key)
	t, r := pb.DestructDiscreteLogKnowledge(key.Proof)

	err = zkp.CheckDiscreteLogKnowledgeProof(*zkp.G, k, t, r, *zkp.P, *zkp.Q)
	if err != nil {
		log.Fatalf("Received incorrect zero-knowledge proof. Key=%v, t=%v, r=%v", k, t, r)
	}

	return
}

func receiveRound1(state interface{}, results []*pb.OuterStruct) {
	s := getState(state)
	var key pb.Key

	s.keys = append(s.keys, s.myPublicKey)

	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].Data, &key)
		if err != nil {
			fmt.Println(err)
			log.Fatalf("Failed to unmarshal pb.Key.\n")
		}
		var k big.Int
		k.SetBytes(key.Key)
		s.keys = append(s.keys, k)
	}

	// Calculating final public key
	// TODO SHOULD THIS BE MOD P? Probably doesn't matter, but just for computational practicality
	s.publicKey.Set(zkp.One)
	for _, key := range s.keys {
		s.publicKey.Mul(&s.publicKey, &key)
		s.publicKey.Mod(&s.publicKey, zkp.P)
	}

	log.Printf("Calculated public key: %v\n", s.publicKey.String())
}

// ROUND 2 FUNCTIONS

func computeRound2(state interface{}) proto.Message {
	s := getState(state)

	var alphasInts, betasInts []big.Int

	var proofs []*pb.EqualsOneOfTwo

	var j uint
	for j = 0; j < zkp.K_Mill; j++ {
		var alphaJ, betaJ, rJ big.Int
		rJ.Rand(zkp.RandGen, zkp.Q)

		// log.Printf("r_%v,%v = %v\n", *id, j, rJ.String())

		// get the j-th bit of bid
		Bij := (((*bid) >> j) & 1)
		log.Printf("B_%v,%v = %v", *id, j, Bij)

		// calculate alpha_j
		// log.Printf("Public key: %v, Rj: %v, P: %v\n", s.publicKey, rJ, *zkp.P)
		alphaJ.Exp(&s.publicKey, &rJ, zkp.P) // TODO mod P?
		if Bij == 1 {
			alphaJ.Mul(&alphaJ, zkp.Y_Mill)
			alphaJ.Mod(&alphaJ, zkp.P)
		}

		// calculate beta_j
		betaJ.Exp(zkp.G, &rJ, zkp.P)
		// log.Printf("alpha_%v: %v\n", j, alphaJ)
		// log.Printf("beta_%v: %v\n", j, betaJ)

		alphasInts = append(alphasInts, alphaJ)
		betasInts = append(betasInts, betaJ)

		var m big.Int
		if Bij == 1 {
			m.Set(zkp.Y_Mill)
		} else {
			m.Set(zkp.One)
		}
		a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2 :=
			zkp.EncryptedValueIsOneOfTwo(m, s.publicKey, rJ, *zkp.G,
				*zkp.Y_Mill, *zkp.P, *zkp.Q)

		proofs = append(proofs, pb.CreateIsOneOfTwo(a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2))
	}

	s.myAlphasBetas = &AlphaBetaStruct{
		alphas: alphasInts,
		betas:  betasInts,
	}

	fmt.Println("Length of proofs")
	fmt.Println(len(proofs))

	return &AlphaBeta{
		Alphas: pb.BigIntSliceToByteSlice(alphasInts),
		Betas:  pb.BigIntSliceToByteSlice(betasInts),
		Proofs: proofs,
	}
}

func checkRound2(state interface{}, result *pb.OuterStruct) (err error) {
	s := getState(state)
	var in AlphaBeta

	err = proto.Unmarshal(result.Data, &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal AlphaBeta.\n")
	}

	fmt.Println(len(in.Alphas))
	fmt.Println(len(in.Betas))
	fmt.Println(len(in.Proofs))
	fmt.Println(uint(len(in.Proofs)))
	fmt.Println(zkp.K_Mill)

	if len(in.Alphas) != len(in.Betas) || len(in.Proofs) != len(in.Betas) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Fatalf("Incorrect number of shit")
	}

	alphas := pb.ByteSliceToBigIntSlice(in.Alphas)
	betas := pb.ByteSliceToBigIntSlice(in.Betas)

	for i := 0; i < len(in.Alphas); i++ {
		a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2 :=
			pb.DestructIsOneOfTwo(in.Proofs[i])

		if err := zkp.CheckEncryptedValueIsOneOfTwo(alphas[i], betas[i], *zkp.P, *zkp.Q,
			a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2,
			*zkp.G, s.publicKey, *zkp.Y_Mill); err != nil {
			log.Fatalf("Received incorrect zero-knowledge proof for alpha/beta")
		}
	}

	return
}

func receiveRound2(state interface{}, results []*pb.OuterStruct) {
	s := getState(state)
	var alphabeta AlphaBeta
	s.theirAlphasBetas = &AlphaBetaStruct{}

	// Wait for alphas and betas of other client
	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].Data, &alphabeta)
		if err != nil {
			log.Fatalf("Failed to unmarshal AlphaBeta.\n")
		}
		s.theirAlphasBetas.alphas = pb.ByteSliceToBigIntSlice(alphabeta.Alphas)
		s.theirAlphasBetas.betas = pb.ByteSliceToBigIntSlice(alphabeta.Betas)
	}
}

// ROUND 3 FUNCTIONS

func computeRound3(state interface{}) proto.Message {
	s := getState(state)

	var gds *GammaDeltaStruct
	if *id == 0 {
		gds = MillionaireCalculateGammaDelta(s.myAlphasBetas.alphas, s.theirAlphasBetas.alphas,
			s.myAlphasBetas.betas, s.theirAlphasBetas.betas, *zkp.Y_Mill, *zkp.P)
	} else {
		gds = MillionaireCalculateGammaDelta(s.theirAlphasBetas.alphas, s.myAlphasBetas.alphas,
			s.theirAlphasBetas.betas, s.myAlphasBetas.betas, *zkp.Y_Mill, *zkp.P)
	}
	// TODO for now just set both
	s.myGammasDeltas = gds
	s.theirGammasDeltas = gds

	if *id == 0 {
		// if our ID is 0 we verifiably secret shuffle
		e := zkp.AlphasBetasToCipherTexts(s.myGammasDeltas.Gammas, s.myGammasDeltas.Deltas)
		E, c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z :=
			zkp.RandomlyPermute(e, *zkp.P, *zkp.Q, *zkp.G, s.publicKey)
		permutedGammas, permutedDeltas := zkp.CipherTextsToAlphasBetas(E)
		s.myGammasDeltas.Gammas = permutedGammas
		s.myGammasDeltas.Deltas = permutedDeltas
		return &MixedOutput{
			Gammas: pb.BigIntSliceToByteSlice(permutedGammas),
			Deltas: pb.BigIntSliceToByteSlice(permutedDeltas),
			Proof:  pb.CreateVerifiableSecretShuffle(c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z),
		}
	}

	return nil
}

func checkRound3(state interface{}, result *pb.OuterStruct) (err error) {
	log.Printf("About to check for round %v", result.Stepid)
	// if we are ID 0, we should not receive anything in this round.
	if *id == 0 {
		return nil
	}
	// otherwise, we have received shuffled gammas/deltas
	s := getState(state)
	var in MixedOutput

	err = proto.Unmarshal(result.Data, &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal MixedOutput.\n")
	}

	fmt.Println(len(in.Gammas))
	fmt.Println(len(in.Deltas))

	if len(in.Gammas) != len(in.Deltas) {
		log.Fatalf("Incorrect number of gammas/deltas received from id %v", result.Clientid)
	}

	gammas := pb.ByteSliceToBigIntSlice(in.Gammas)
	deltas := pb.ByteSliceToBigIntSlice(in.Deltas)

	e := zkp.AlphasBetasToCipherTexts(s.myGammasDeltas.Gammas, s.myGammasDeltas.Deltas)
	E := zkp.AlphasBetasToCipherTexts(gammas, deltas)

	c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z :=
		pb.DestructVerifiableSecretShuffle(in.Proof)

	log.Printf("Continuing checking a: %v!", result.Stepid)
	err = zkp.CheckVerifiableSecretShuffle(e, E, *zkp.P, *zkp.Q, *zkp.G, s.publicKey,
		c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z)

	log.Printf("Continuing checking b: %v!", result.Stepid)
	if err != nil {
		log.Fatalf("Received incorrect zero knowledge proof for permuted output 1")
	}

	log.Printf("Checked for round %v!", result.Stepid)
	return err
}

func receiveRound3(state interface{}, results []*pb.OuterStruct) {
	log.Printf("About to receive for round %v", results[1-*id].Stepid)
	if *id == 0 {
		return // nothing to actually receive here for ID 0, do not try to demartial
	}
	s := getState(state)
	var mixedOutput MixedOutput

	// Wait for alphas and betas of other client
	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].Data, &mixedOutput)
		if err != nil {
			log.Fatalf("Failed to unmarshal MixedOutput.\n")
		}
		s.theirGammasDeltas.Gammas = pb.ByteSliceToBigIntSlice(mixedOutput.Gammas)
		s.theirGammasDeltas.Deltas = pb.ByteSliceToBigIntSlice(mixedOutput.Deltas)
	}
}

// ROUND 4 FUNCTIONS

func computeRound4(state interface{}) proto.Message {
	if *id == 0 {
		return nil // nothing to actually send here for ID 0
	}

	s := getState(state)
	// TODO
	// if our ID is 1 we verifiably secret shuffle what we received from ID 0 last round
	e := zkp.AlphasBetasToCipherTexts(s.theirGammasDeltas.Gammas, s.theirGammasDeltas.Deltas)
	E, c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z :=
		zkp.RandomlyPermute(e, *zkp.P, *zkp.Q, *zkp.G, s.publicKey)
	permutedGammas, permutedDeltas := zkp.CipherTextsToAlphasBetas(E)
	s.myGammasDeltas.Gammas = permutedGammas
	s.myGammasDeltas.Deltas = permutedDeltas
	s.theirGammasDeltas.Gammas = permutedGammas
	s.theirGammasDeltas.Deltas = permutedDeltas
	return &MixedOutput{
		Gammas: pb.BigIntSliceToByteSlice(permutedGammas),
		Deltas: pb.BigIntSliceToByteSlice(permutedDeltas),
		Proof:  pb.CreateVerifiableSecretShuffle(c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z),
	}
}

func checkRound4(state interface{}, result *pb.OuterStruct) (err error) {
	log.Printf("About to check for round %v", result.Stepid)
	// if we are ID 1, we should not receive anything real in this round.
	if *id == 1 {
		return nil
	}
	// otherwise, we have received shuffled gammas/deltas
	s := getState(state)
	var in MixedOutput

	err = proto.Unmarshal(result.Data, &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal MixedOutput.\n")
	}

	fmt.Println(len(in.Gammas))
	fmt.Println(len(in.Deltas))

	if len(in.Gammas) != len(in.Deltas) {
		log.Fatalf("Incorrect number of gammas/deltas received from id %v", result.Clientid)
	}

	gammas := pb.ByteSliceToBigIntSlice(in.Gammas)
	deltas := pb.ByteSliceToBigIntSlice(in.Deltas)

	e := zkp.AlphasBetasToCipherTexts(s.myGammasDeltas.Gammas, s.myGammasDeltas.Deltas)
	E := zkp.AlphasBetasToCipherTexts(gammas, deltas)

	c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z :=
		pb.DestructVerifiableSecretShuffle(in.Proof)

	err = zkp.CheckVerifiableSecretShuffle(e, E, *zkp.P, *zkp.Q, *zkp.G, s.publicKey,
		c, cd, cD, ER, f, fd, yd, zd, F, yD, zD, Z)

	if err != nil {
		log.Fatalf("Received incorrect zero knowledge proof for permuted output 2")
	}

	return err
}

func receiveRound4(state interface{}, results []*pb.OuterStruct) {
	log.Printf("About to receive for round %v", results[1-*id].Stepid)
	// if we are ID 1, we should not receive anything real in this round.
	if *id == 1 {
		return
	}

	s := getState(state)
	var mixedOutput MixedOutput

	// Wait for alphas and betas of other client
	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].Data, &mixedOutput)
		if err != nil {
			log.Fatalf("Failed to unmarshal MixedOutput.\n")
		}
		s.theirGammasDeltas.Gammas = pb.ByteSliceToBigIntSlice(mixedOutput.Gammas)
		s.theirGammasDeltas.Deltas = pb.ByteSliceToBigIntSlice(mixedOutput.Deltas)
		s.myGammasDeltas.Gammas = s.theirGammasDeltas.Gammas
		s.myGammasDeltas.Deltas = s.theirGammasDeltas.Deltas
	}
}

// ROUND 5 FUNCTIONS

func computeRound5(state interface{}) proto.Message {
	s := getState(state)
	var proofs []*pb.DiscreteLogEquality

	s.myExponentiatedGammasDeltas = &GammaDeltaStruct{}

	// compute exponentiated gamma and delta
	// TODO for now myGammasDeltas
	for j := 0; j < int(zkp.K_Mill); j++ {
		// log.Println("Beginning random exponentiation2")

		// this is our random exponent
		var m big.Int
		m.Rand(zkp.RandGen, zkp.Q)

		var newGamma, newDelta big.Int
		newGamma.Exp(&s.myGammasDeltas.Gammas[j], &m, zkp.P)
		newDelta.Exp(&s.myGammasDeltas.Deltas[j], &m, zkp.P)
		// log.Println("Beginning random exponentiation3")

		log.Printf("Computed m_%v = %v, gamma_%v = %v, delta_%v = %v\n", j, m.String(), j, newGamma.String(), j, newDelta.String())

		s.myExponentiatedGammasDeltas.Gammas = append(
			s.myExponentiatedGammasDeltas.Gammas, newGamma)

		s.myExponentiatedGammasDeltas.Deltas = append(
			s.myExponentiatedGammasDeltas.Deltas, newDelta)

		// to pass the bases to the zkp generator
		gs := []big.Int{s.myGammasDeltas.Gammas[j], s.myGammasDeltas.Deltas[j]}
		// log.Println("Beginning random exponentiation4")

		// create proof and add it to proof list
		ts, r := zkp.DiscreteLogEquality(m, gs, *zkp.P, *zkp.Q)

		// TODO remove
		//checking the proof here before we send it
		var results, results2 []big.Int
		var a, b big.Int
		a.Exp(&gs[0], &m, zkp.P)
		b.Exp(&gs[1], &m, zkp.P)
		results = append(results, a)
		results = append(results, b)
		results2 = append(results2, s.myExponentiatedGammasDeltas.Gammas[j])
		results2 = append(results2, s.myExponentiatedGammasDeltas.Deltas[j])
		// err := zkp.CheckDiscreteLogEqualityProof(gs, results, ts, r, *zkp.P, *zkp.Q)
		// // log.Printf("Creating proof.\nBases=%v\nExponent=%v\nResults=%v\nResults2=%v\nTs=%vn,R=%v\n", gs, m, results, results2, ts, r)
		// if err != nil {
		// 	log.Printf("WHAT THE heck %v\n", err)
		// } else {
		// 	// log.Printf("Yay!!! Correct exponentiatedGammas exponentiatedDeltas proof")
		// }
		// TODO done

		proofs = append(proofs, pb.CreateDiscreteLogEquality(ts, r))

		// log.Println("Beginning random exponentiation7")
	}

	return &RandomizedOutput{
		Gammas: pb.BigIntSliceToByteSlice(s.myExponentiatedGammasDeltas.Gammas),
		Deltas: pb.BigIntSliceToByteSlice(s.myExponentiatedGammasDeltas.Deltas),
		Proofs: proofs,
	}
}

func checkRound5(state interface{}, result *pb.OuterStruct) (err error) {
	s := getState(state)
	var in RandomizedOutput

	err = proto.Unmarshal(result.Data, &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal RandomizedOutput.\n")
	}

	if len(in.Gammas) != len(in.Deltas) || len(in.Proofs) != len(in.Deltas) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Fatalf("Incorrect number of shit4")
	}

	gammas := pb.ByteSliceToBigIntSlice(in.Gammas)
	deltas := pb.ByteSliceToBigIntSlice(in.Deltas)

	for j := 0; j < len(in.Gammas); j++ {
		log.Printf("RECEIVED gamma_%v = %v, delta_%v = %v\n", j, gammas[j].String(), j, deltas[j].String())

		bases := []big.Int{s.theirGammasDeltas.Gammas[j], s.theirGammasDeltas.Deltas[j]}
		results := []big.Int{gammas[j], deltas[j]}

		// set proof values
		ts, r := pb.DestructDiscreteLogEquality(in.Proofs[j])

		if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
			log.Fatalf("Received incorrect zero-knowledge proof for exponentiated gammas/deltas")
		}
	}

	return
}

func receiveRound5(state interface{}, results []*pb.OuterStruct) {
	s := getState(state)
	var randomizedoutput RandomizedOutput

	s.theirExponentiatedGammasDelta = &GammaDeltaStruct{}

	// Wait for alphas and betas of other client
	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].Data, &randomizedoutput)
		if err != nil {
			log.Fatalf("Failed to unmarshal RandomizedOutput.\n")
		}

		s.theirExponentiatedGammasDelta.Gammas = pb.ByteSliceToBigIntSlice(randomizedoutput.Gammas)
		s.theirExponentiatedGammasDelta.Deltas = pb.ByteSliceToBigIntSlice(randomizedoutput.Deltas)
	}
}

// ROUND 6 FUNCTIONS

func computeRound6(state interface{}) proto.Message {
	s := getState(state)
	// log.Println("Beginning decryption")

	var proofs []*pb.DiscreteLogEquality

	s.myPhis = new(PhiStruct)
	s.phisBeforeExponentiation = new(PhiStruct)

	// compute exponentiated gamma and delta
	// TODO for now myGammasDeltas
	for i := 0; i < int(zkp.K_Mill); i++ {
		// calculate phi
		var phi, phi2 big.Int
		phi.Mul(&s.myExponentiatedGammasDeltas.Deltas[i], &s.theirExponentiatedGammasDelta.Deltas[i])
		phi.Mod(&phi, zkp.P)
		// before exponentiating, add it to our list for checking the ZKP
		phi2.Set(&phi)
		s.phisBeforeExponentiation.Phis = append(s.phisBeforeExponentiation.Phis, phi2)

		log.Printf("COMPUTED: Before exponentiation, phi_%v = %v\n", i, phi2.String())

		phi.Exp(&phi, &s.myPrivateKey, zkp.P)
		s.myPhis.Phis = append(s.myPhis.Phis, phi)

		log.Printf("COMPUTED: phi_%v = %v\n", i, phi.String())

		// to pass the bases to the zkp generator
		var gs []big.Int
		gs = append(gs, phi2)
		gs = append(gs, *zkp.G)

		// create proof and add it to proof list
		ts, r := zkp.DiscreteLogEquality(s.myPrivateKey, gs, *zkp.P, *zkp.Q)
		// log.Printf("Creating proof.\nBases=%v\nExponent=%v\nTs=%vn,R=%v\n", gs, s.myPrivateKey, ts, r)

		proofs = append(proofs, pb.CreateDiscreteLogEquality(ts, r))
	}

	return &DecryptionInfo{
		Phis:   pb.BigIntSliceToByteSlice(s.myPhis.Phis),
		Proofs: proofs,
	}
}

func checkRound6(state interface{}, result *pb.OuterStruct) (err error) {
	s := getState(state)
	var in DecryptionInfo

	err = proto.Unmarshal(result.Data, &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal DecryptionInfo.\n")
	}

	if len(in.Phis) != len(in.Proofs) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Printf("len of phis=%v, len of proofs=%v, k=%v\n", len(in.Phis), uint(len(in.Proofs)), zkp.K_Mill)
		log.Fatalf("Incorrect number of shit6")
	}

	phis := pb.ByteSliceToBigIntSlice(in.Phis)

	for j := 0; j < len(in.Phis); j++ {
		log.Printf("RECEIVED: phi_%v = %v\n", j, phis[j].String())

		var bases, results []big.Int
		// proof equality of logarithms of the received phi and their public key
		bases = append(bases, s.phisBeforeExponentiation.Phis[j])
		bases = append(bases, *zkp.G)
		results = append(results, phis[j])
		results = append(results, s.keys[1]) // their public key!

		// set proof values
		ts, r := pb.DestructDiscreteLogEquality(in.Proofs[j])

		// log.Printf("Checking proof.\nBases=%v\nResults=%v\nTs=%vn,R=%v\n", bases, results, ts, r)
		if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
			fmt.Println(err)
			log.Fatalf("Received incorrect zero-knowledge proof for phis")
		}
	}

	return
}

func receiveRound6(state interface{}, results []*pb.OuterStruct) {
	s := getState(state)
	var decInfo DecryptionInfo
	err := proto.Unmarshal(results[1-*id].Data, &decInfo) // just need their result
	if err != nil {
		log.Fatalf("Failed to unmarshal DecryptionInfo.\n")
	}
	log.Printf("%v\n", decInfo)
	// Calculate the final shit (division + which one is bigger)
	phis := pb.ByteSliceToBigIntSlice(decInfo.Phis)
	for j := 0; j < int(zkp.K_Mill); j++ {

		v := MillionaireCalculateV(s.myExponentiatedGammasDeltas.Gammas[j],
			s.theirExponentiatedGammasDelta.Gammas[j],
			s.myPhis.Phis[j],
			phis[j],
			*zkp.P)

		log.Printf("v_%v = %v\n", j, v)

		if v.Cmp(zkp.One) == 0 {
			log.Fatalf("ID 0 is the winner\n")
		}
	}
	log.Fatalf("ID 1 is the winner\n")
}

func getID(hosts []string) int {
	for i, host := range hosts {
		if host == *myAddress {
			return i
		}
	}

	return -1
}

func main() {
	flag.Parse()

	myState := &state{}

	hosts := lib.GetHosts()
	*id = getID(hosts)

	lib.Init(*id)
	myAddr := hosts[*id]

	fmt.Println(myAddr)

	go lib.RunServer(myAddr)

	lib.InitClients(hosts, myAddr)

	rounds := []lib.Round{
		{computeRound1, checkRound1, receiveRound1},
		{computeRound2, checkRound2, receiveRound2},
		{computeRound3, checkRound3, receiveRound3},
		{computeRound4, checkRound4, receiveRound4},
		{computeRound5, checkRound5, receiveRound5},
		{computeRound6, checkRound6, receiveRound6},
	}

	lib.Register(rounds, myState)
}
