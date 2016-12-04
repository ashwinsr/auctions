package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"

	"github.com/ashwinsr/auctions/lib"
	"github.com/ashwinsr/auctions/pb"
	"github.com/ashwinsr/auctions/zkp"
	"github.com/golang/protobuf/proto"

	// "net/http"
	_ "net/http/pprof"
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
	id = flag.Int("id", -1, "ID")

	// TODO millionaire specific
	bid = flag.Uint("bid", 0, "Amount of money")
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
	// Create proto structure of zkp
	zkpPrivKey := &pb.DiscreteLogKnowledge{T: t.Bytes(), R: r.Bytes()}

	return &pb.Key{
		Key:   s.myPublicKey.Bytes(),
		Proof: zkpPrivKey,
	}
}

func checkRound1(state interface{}, result *pb.OuterStruct) (err error) {
	var key pb.Key

	var k, t, r big.Int

	err = proto.Unmarshal(result.GetData(), &key)
	if err != nil {
		fmt.Println(err)
		log.Fatalf("Failed to unmarshal pb.Key.\n")
	}

	k.SetBytes(key.GetKey())
	t.SetBytes(key.GetProof().GetT())
	r.SetBytes(key.GetProof().GetR())

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
		err := proto.Unmarshal(results[i].GetData(), &key)
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

	var alphas, betas [][]byte
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

		alphas = append(alphas, alphaJ.Bytes())
		alphasInts = append(alphasInts, alphaJ)
		betas = append(betas, betaJ.Bytes())
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

		proofs = append(proofs, &pb.EqualsOneOfTwo{
			A_1: a_1.Bytes(),
			A_2: a_2.Bytes(),
			B_1: b_1.Bytes(),
			B_2: b_2.Bytes(),
			D_1: d_1.Bytes(),
			D_2: d_2.Bytes(),
			R_1: r_1.Bytes(),
			R_2: r_2.Bytes(),
		})
	}

	s.myAlphasBetas = &AlphaBetaStruct{
		alphas: alphasInts,
		betas:  betasInts,
	}

	fmt.Println("Length of proofs")
	fmt.Println(len(proofs))

	return &pb.AlphaBeta{
		Alphas: alphas,
		Betas:  betas,
		Proofs: proofs,
	}
}

func checkRound2(state interface{}, result *pb.OuterStruct) (err error) {
	s := getState(state)
	var in pb.AlphaBeta

	err = proto.Unmarshal(result.GetData(), &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal pb.AlphaBeta.\n")
	}

	fmt.Println(len(in.Alphas))
	fmt.Println(len(in.Betas))
	fmt.Println(len(in.Proofs))
	fmt.Println(uint(len(in.Proofs)))
	fmt.Println(zkp.K_Mill)

	if len(in.Alphas) != len(in.Betas) || len(in.Proofs) != len(in.Betas) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Fatalf("Incorrect number of shit")
	}

	for i := 0; i < len(in.Alphas); i++ {
		var alpha, beta, a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2 big.Int
		alpha.SetBytes(in.Alphas[i])
		beta.SetBytes(in.Betas[i])
		a_1.SetBytes(in.Proofs[i].A_1)
		a_2.SetBytes(in.Proofs[i].A_2)
		b_1.SetBytes(in.Proofs[i].B_1)
		b_2.SetBytes(in.Proofs[i].B_2)
		d_1.SetBytes(in.Proofs[i].D_1)
		d_2.SetBytes(in.Proofs[i].D_2)
		r_1.SetBytes(in.Proofs[i].R_1)
		r_2.SetBytes(in.Proofs[i].R_2)

		if err := zkp.CheckEncryptedValueIsOneOfTwo(alpha, beta, *zkp.P, *zkp.Q,
			a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2,
			*zkp.G, s.publicKey, *zkp.Y_Mill); err != nil {
			log.Fatalf("Received incorrect zero-knowledge proof for alpha/beta")
		}
	}

	return
}

func receiveRound2(state interface{}, results []*pb.OuterStruct) {
	s := getState(state)
	var alphabeta pb.AlphaBeta
	s.theirAlphasBetas = &AlphaBetaStruct{}

	// Wait for alphas and betas of other client
	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].GetData(), &alphabeta)
		if err != nil {
			log.Fatalf("Failed to unmarshal pb.AlphaBeta.\n")
		}
		for j := 0; j < len(alphabeta.GetAlphas()); j++ {
			s.theirAlphasBetas.alphas = append(s.theirAlphasBetas.alphas, *new(big.Int).SetBytes(alphabeta.GetAlphas()[j]))
			s.theirAlphasBetas.betas = append(s.theirAlphasBetas.betas, *new(big.Int).SetBytes(alphabeta.GetBetas()[j]))
		}
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

	return nil
}

func checkRound3(state interface{}, result *pb.OuterStruct) (err error) {
	return nil
}

func receiveRound3(state interface{}, results []*pb.OuterStruct) {
	return
}

// ROUND 4 FUNCTIONS

func computeRound4(state interface{}) proto.Message {
	return nil
}

func checkRound4(state interface{}, result *pb.OuterStruct) (err error) {
	return nil
}

func receiveRound4(state interface{}, results []*pb.OuterStruct) {
	return
}

// ROUND 5 FUNCTIONS

func computeRound5(state interface{}) proto.Message {
	s := getState(state)
	var proofs []*pb.DiscreteLogEquality

	var exponentiatedGammas, exponentiatedDeltas [][]byte

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

		// for the protobuf struct
		exponentiatedGammas = append(exponentiatedGammas, newGamma.Bytes())
		exponentiatedDeltas = append(exponentiatedDeltas, newDelta.Bytes())

		// to pass the bases to the zkp generator
		var gs []big.Int
		gs = append(gs, s.myGammasDeltas.Gammas[j])
		gs = append(gs, s.myGammasDeltas.Deltas[j])
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
		err := zkp.CheckDiscreteLogEqualityProof(gs, results, ts, r, *zkp.P, *zkp.Q)
		// log.Printf("Creating proof.\nBases=%v\nExponent=%v\nResults=%v\nResults2=%v\nTs=%vn,R=%v\n", gs, m, results, results2, ts, r)
		if err != nil {
			log.Printf("WHAT THE heck %v\n", err)
		} else {
			// log.Printf("Yay!!! Correct exponentiatedGammas exponentiatedDeltas proof")
		}
		// TODO done

		// log.Println("Beginning random exponentiation5")
		var proof pb.DiscreteLogEquality
		for _, t := range ts {
			proof.Ts = append(proof.Ts, t.Bytes())
		}

		// log.Println("Beginning random exponentiation6")
		proof.R = r.Bytes()
		proofs = append(proofs, &proof)

		// log.Println("Beginning random exponentiation7")
	}

	return &pb.RandomizedOutput{
		Gammas: exponentiatedGammas,
		Deltas: exponentiatedDeltas,
		Proofs: proofs,
	}
}

func checkRound5(state interface{}, result *pb.OuterStruct) (err error) {
	var in pb.RandomizedOutput

	err = proto.Unmarshal(result.GetData(), &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal pb.RandomizedOutput.\n")
	}

	if len(in.Gammas) != len(in.Deltas) || len(in.Proofs) != len(in.Deltas) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Fatalf("Incorrect number of shit4")
	}

	for j := 0; j < len(in.Gammas); j++ {
		var gamma, delta big.Int
		gamma.SetBytes(in.Gammas[j])
		delta.SetBytes(in.Deltas[j])

		log.Printf("RECEIVED gamma_%v = %v, delta_%v = %v\n", j, gamma.String(), j, delta.String())

		var bases, results, ts []big.Int
		results = append(results, gamma)
		results = append(results, delta)

		// set proof values
		var r big.Int
		r.SetBytes(in.Proofs[j].R)
		for _, t := range in.Proofs[j].Ts {
			var t_temp big.Int
			t_temp.SetBytes(t)
			ts = append(ts, t_temp)
		}

		if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
			log.Fatalf("Received incorrect zero-knowledge proof for exponentiated gammas/deltas")
		}
	}

	return
}

func receiveRound5(state interface{}, results []*pb.OuterStruct) {
	s := getState(state)
	var randomizedoutput pb.RandomizedOutput

	s.theirExponentiatedGammasDelta = &GammaDeltaStruct{}

	// Wait for alphas and betas of other client
	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].GetData(), &randomizedoutput)
		if err != nil {
			log.Fatalf("Failed to unmarshal pb.RandomizedOutput.\n")
		}
		for j := 0; j < len(randomizedoutput.GetGammas()); j++ {
			s.theirExponentiatedGammasDelta.Gammas = append(s.theirExponentiatedGammasDelta.Gammas, *new(big.Int).SetBytes(randomizedoutput.GetGammas()[j]))
			s.theirExponentiatedGammasDelta.Deltas = append(s.theirExponentiatedGammasDelta.Deltas, *new(big.Int).SetBytes(randomizedoutput.GetDeltas()[j]))
		}
	}
}

// ROUND 6 FUNCTIONS

func computeRound6(state interface{}) proto.Message {
	s := getState(state)
	// log.Println("Beginning decryption")

	var proofs []*pb.DiscreteLogEquality

	var phis [][]byte

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

		// for the protobuf struct
		phis = append(phis, phi.Bytes())

		// to pass the bases to the zkp generator
		var gs []big.Int
		gs = append(gs, phi2)
		gs = append(gs, *zkp.G)

		// create proof and add it to proof list
		ts, r := zkp.DiscreteLogEquality(s.myPrivateKey, gs, *zkp.P, *zkp.Q)
		// log.Printf("Creating proof.\nBases=%v\nExponent=%v\nTs=%vn,R=%v\n", gs, s.myPrivateKey, ts, r)

		var proof pb.DiscreteLogEquality
		for _, t := range ts {
			proof.Ts = append(proof.Ts, t.Bytes())
		}

		proof.R = r.Bytes()
		proofs = append(proofs, &proof)
	}

	return &pb.DecryptionInfo{
		Phis:   phis,
		Proofs: proofs,
	}
}

func checkRound6(state interface{}, result *pb.OuterStruct) (err error) {
	s := getState(state)
	var in pb.DecryptionInfo

	err = proto.Unmarshal(result.GetData(), &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal pb.DecryptionInfo.\n")
	}

	if len(in.Phis) != len(in.Proofs) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Printf("len of phis=%v, len of proofs=%v, k=%v\n", len(in.Phis), uint(len(in.Proofs)), zkp.K_Mill)
		log.Fatalf("Incorrect number of shit6")
	}

	for j := 0; j < len(in.Phis); j++ {
		var phi big.Int
		phi.SetBytes(in.Phis[j])

		log.Printf("RECEIVED: phi_%v = %v\n", j, phi.String())

		var bases, results, ts []big.Int
		// proof equality of logarithms of the received phi and their public key
		bases = append(bases, s.phisBeforeExponentiation.Phis[j])
		bases = append(bases, *zkp.G)
		results = append(results, phi)
		results = append(results, s.keys[1]) // their public key!

		// set proof values
		var r big.Int
		r.SetBytes(in.Proofs[j].R)
		for _, t := range in.Proofs[j].Ts {
			var t_temp big.Int
			t_temp.SetBytes(t)
			ts = append(ts, t_temp)
		}

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
	var decInfo pb.DecryptionInfo
	err := proto.Unmarshal(results[1-*id].GetData(), &decInfo) // just need their result
	if err != nil {
		log.Fatalf("Failed to unmarshal pb.DecryptionInfo.\n")
	}
	log.Printf("%v\n", decInfo)
	// Calculate the final shit (division + which one is bigger)
	for j := 0; j < int(zkp.K_Mill); j++ {
		// deleteMe1 := s.myExponentiatedGammasDeltas.Gammas[j]
		// deleteMe2 := s.theirExponentiatedGammasDelta.Gammas[j]
		// deleteMe3 := s.myPhis.Phis[j]
		// deleteMe4 := s.theirPhis.Phis[j] // TODO theirPhis unused
		// _ = deleteMe1
		// _ = deleteMe2
		// _ = deleteMe3
		// _ = deleteMe4

		var phi big.Int
		phi.SetBytes(decInfo.Phis[j])

		v := MillionaireCalculateV(s.myExponentiatedGammasDeltas.Gammas[j], s.theirExponentiatedGammasDelta.Gammas[j], s.myPhis.Phis[j], phi, *zkp.P)
		log.Printf("v_%v = %v\n", j, v)
		if v.Cmp(zkp.One) == 0 {
			log.Fatalf("ID 0 is the winner\n")
		}
	}
	log.Fatalf("ID 1 is the winner\n")
}

func main() {
	flag.Parse()

	myState := &state{}
	lib.Init(*id)

	hosts := lib.GetHosts()
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

	// TODO do this better
	for {
	}
}
