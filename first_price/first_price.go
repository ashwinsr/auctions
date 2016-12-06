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

var (
	id  = flag.Int("id", -1, "ID")
	bid = flag.Uint("bid", 0, "Amount of money")
)

var K uint = 27

type AlphaBetaStruct struct {
	alphas, betas []big.Int
}

type FpState struct {
	myPrivateKey big.Int
	myPublicKey  big.Int
	keys         []big.Int
	publicKey    big.Int
	currRound    int

	AlphasBetas []*AlphaBetaStruct // TODO Akshay remember to initialize
}

func main() {
	flag.Parse()

	myState := &FpState{}
	lib.Init(*id)

	hosts := lib.GetHosts()
	myAddr := hosts[*id]

	fmt.Println(myAddr)

	go lib.RunServer(myAddr)

	lib.InitClients(hosts, myAddr)

	rounds := []lib.Round{
		{computeRound1, checkRound1, receiveRound1},
		{computeRound2, checkRound2, receiveRound2},
		// {computeRound3, checkRound3, receiveRound3},
		// {computeRound4, checkRound4, receiveRound4},
		// {computeRound5, checkRound5, receiveRound5},
		// {computeRound6, checkRound6, receiveRound6},
	}

	lib.Register(rounds, myState)
}

func getFpState(state interface{}) (s *FpState) {
	s, ok := state.(*FpState)
	if !ok {
		log.Fatalf("Failed to typecast FpState.\n")
	}
	return
}

func computeArrayRangeProduct(arr []big.Int, start, end uint) big.Int {
	var product big.Int
	product.Set(zkp.One)

	for i := start; i < end; i++ {
		product.Mul(&product, &arr[i])
		product.Mod(&product, zkp.P) // TODO Check Mod
	}

	return product
}

func checkRound1(state interface{}, result *pb.OuterStruct) (err error) {
	var key pb.Key

	var k, t, r big.Int

	err = proto.Unmarshal(result.Data, &key)
	if err != nil {
		log.Fatalf("Failed to unmarshal pb.Key.\n")
	}

	k.SetBytes(key.Key)
	t.SetBytes(key.GetProof().T)
	r.SetBytes(key.GetProof().R)

	err = zkp.CheckDiscreteLogKnowledgeProof(*zkp.G, k, t, r, *zkp.P, *zkp.Q)
	if err != nil {
		log.Fatalf("Received incorrect zero-knowledge proof. Key=%v, t=%v, r=%v", k, t, r)
	}

	return
}

func checkRound2(state interface{}, result *pb.OuterStruct) (err error) {
	s := getFpState(state)
	var in Round1

	err = proto.Unmarshal(result.Data, &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal pb.Round1.\n")
	}

	if len(in.Alphas) != len(in.Betas) || len(in.Proofs) != len(in.Betas) || uint(len(in.Proofs)) != K {
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

	// TODO Akshay remember to check the other proof here, in.proof

	return
}

func receiveRound1(FpState interface{}, results []*pb.OuterStruct) {
	s := getFpState(FpState)
	var key pb.Key

	s.keys = append(s.keys, s.myPublicKey)

	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].Data, &key)
		if err != nil {
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

func receiveRound2(FpState interface{}, results []*pb.OuterStruct) {
	s := getFpState(FpState)

	var round1 Round1

	// Atore all received alphas and betas
	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].Data, &round1)
		if err != nil {
			log.Fatalf("Failed to unmarshal Round1.\n")
		}

		var alphas, betas []big.Int

		for j := 0; j < len(round1.Alphas); j++ {
			alphas = append(alphas, *new(big.Int).SetBytes(round1.Alphas[j]))
			betas = append(betas, *new(big.Int).SetBytes(round1.Betas[j]))
		}

		s.AlphasBetas[results[i].Clientid].alphas = alphas
		s.AlphasBetas[results[i].Clientid].betas = betas
	}
}

func computeRound1(FpState interface{}) proto.Message {
	s := getFpState(FpState)

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

func computeRound2(FpState interface{}) proto.Message {
	s := getFpState(FpState)

	var alphasInts, betasInts []big.Int
	var proofs []*pb.EqualsOneOfTwo
	var sumR big.Int
	sumR.Set(zkp.Zero)
	var j uint
	for j = 0; j < K; j++ {
		var alphaJ, betaJ, rJ big.Int

		rJ.Rand(zkp.RandGen, zkp.Q)
		sumR.Add(&sumR, &rJ)

		alphaJ.Exp(&s.publicKey, &rJ, zkp.P) // TODO mod P?

		if j == *bid {
			alphaJ.Mul(&alphaJ, zkp.Y_Mill)
			alphaJ.Mod(&alphaJ, zkp.P)
		}

		// calculate beta_j
		betaJ.Exp(zkp.G, &rJ, zkp.P)

		alphasInts = append(alphasInts, alphaJ)
		betasInts = append(betasInts, betaJ)

		var m big.Int

		if j == *bid {
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

	s.AlphasBetas[*id].alphas = alphasInts
	s.AlphasBetas[*id].betas = betasInts

	sumR.Mod(&sumR, zkp.Z) // TODO Akshay what is Z?

	var gs []big.Int
	gs = append(gs, s.publicKey)
	gs = append(gs, *zkp.G)

	ts, r := zkp.DiscreteLogEquality(sumR, gs, *zkp.P, *zkp.Q)

	var logEqualityProof pb.DiscreteLogEquality
	for _, t := range ts {
		logEqualityProof.Ts = append(logEqualityProof.Ts, t.Bytes())
	}
	logEqualityProof.R = r.Bytes()

	var round1Proof Round1

	for j = 0; j < K; j++ {
		round1Proof.Proofs = append(round1Proof.Proofs, proofs[j])
		round1Proof.Alphas = append(round1Proof.Alphas, alphasInts[j].Bytes())
		round1Proof.Betas = append(round1Proof.Betas, betasInts[j].Bytes())
	}
	round1Proof.Proof = &logEqualityProof

	return &round1Proof
}
