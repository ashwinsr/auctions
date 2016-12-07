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
	myAddress = flag.String("address", "localhost:1234", "address")
	id        = new(int)
	bid       = flag.Uint("bid", 0, "Amount of money")
)

var K uint = 2

type AlphaBetaStruct struct {
	alphas, betas []big.Int
}

type GammaDeltaStruct struct {
	gammas, deltas []big.Int
}

type FpState struct {
	myPrivateKey big.Int
	myPublicKey  big.Int
	keys         []big.Int
	publicKey    big.Int
	currRound    int

	AlphasBetas                      []*AlphaBetaStruct
	GammasDeltasBeforeExponentiation []*GammaDeltaStruct   // indices (a, i, j)
	GammasDeltasAfterExponentiation  [][]*GammaDeltaStruct // indices (a, i, j)
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

	myState := &FpState{}

	hosts := lib.GetHosts()
	*id = getID(hosts)

	myAddr := hosts[*id]
	lib.Init(*id)

	fmt.Println(myAddr)

	go lib.RunServer(myAddr)

	lib.InitClients(hosts, myAddr)

	rounds := []lib.Round{
		{computePrologue, checkPrologue, receivePrologue},
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

func checkPrologue(state interface{}, result *pb.OuterStruct) (err error) {
	var key pb.Key

	err = proto.Unmarshal(result.Data, &key)
	if err != nil {
		log.Fatalf("Failed to unmarshal pb.Key.\n")
	}

	t, r := pb.DestructDiscreteLogKnowledge(key.Proof)

	var k big.Int
	k.SetBytes(key.Key)

	err = zkp.CheckDiscreteLogKnowledgeProof(*zkp.G, k, t, r, *zkp.P, *zkp.Q)
	if err != nil {
		log.Fatalf("Received incorrect zero-knowledge proof. Key=%v, t=%v, r=%v", k, t, r)
	}

	return
}

func checkRound1(state interface{}, result *pb.OuterStruct) (err error) {
	s := getFpState(state)
	var in Round1

	err = proto.Unmarshal(result.Data, &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal Round1.\n")
	}

	if len(in.Alphas) != len(in.Betas) || len(in.Proofs) != len(in.Betas) || uint(len(in.Proofs)) != K {
		log.Fatalf("Incorrect number of shit1")
	}

	alphas := pb.ByteSliceToBigIntSlice(in.Alphas)
	betas := pb.ByteSliceToBigIntSlice(in.Betas)

	for i := 0; i < len(in.Alphas); i++ {
		a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2 := pb.DestructIsOneOfTwo(in.Proofs[i])

		if err := zkp.CheckEncryptedValueIsOneOfTwo(alphas[i], betas[i], *zkp.P, *zkp.Q,
			a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2,
			*zkp.G, s.publicKey, *zkp.Y_Mill); err != nil {
			log.Fatalf("Received incorrect zero-knowledge proof for alpha/beta")
		}
	}

	// TODO Akshay remember to check the other proof here, in.proof

	return
}

func checkRound2(state interface{}, result *pb.OuterStruct) (err error) {
	s := getFpState(state)
	var in Round2

	err = proto.Unmarshal(result.Data, &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal Round2.\n")
	}

	// TODO need error checking

	// if len(in.Gammas) != len(in.Deltas) || len(in.Proofs) != len(in.Deltas) || uint(len(in.Proofs)) != K {
	// 	log.Fatalf("Incorrect number of shit2: %v %v %v %v", len(in.Gammas), len(in.Deltas), len(in.Proofs), K)
	// }

	if len(in.DoubleGammas) != len(in.DoubleDeltas) ||
		len(in.DoubleDeltas) != len(in.DoubleProofs) ||
		len(in.DoubleGammas) != len(s.keys) {
		log.Fatalf("Incorrect number of outer shit")
	}

	for i := 0; i < len(in.DoubleGammas); i++ {
		if len(in.DoubleGammas[i].Gammas) != len(in.DoubleDeltas[i].Deltas) ||
			len(in.DoubleDeltas[i].Deltas) != len(in.DoubleProofs[i].Proofs) ||
			len(in.DoubleGammas[i].Gammas) != int(K) {
			log.Fatalf("Incorrect number of inner shit %v %v %v\n",
				len(in.DoubleGammas[i].Gammas),
				len(in.DoubleDeltas[i].Deltas),
				len(in.DoubleProofs[i].Proofs))
		}

		gammas := pb.ByteSliceToBigIntSlice(in.DoubleGammas[i].Gammas)
		deltas := pb.ByteSliceToBigIntSlice(in.DoubleDeltas[i].Deltas)

		for j := 0; j < len(in.DoubleGammas[i].Gammas); j++ {
			ts, r := pb.DestructDiscreteLogEquality(in.DoubleProofs[i].Proofs[j])
			log.Printf("Received gamma/delta %v/%v with proof values %v, %v", gammas[j], deltas[j], ts, r)

			// bases are their gammas and deltas before exponentiation!
			bases := []big.Int{
				s.GammasDeltasBeforeExponentiation[result.Clientid].gammas[j],
				s.GammasDeltasBeforeExponentiation[result.Clientid].deltas[j],
			}
			results := []big.Int{gammas[j], deltas[j]}

			if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
				log.Fatalf("Received incorrect zero-knowledge proof for gamma/delta")
			}
		}
	}

	return
}

// TODO decompose! Can be used in both millionaires and auction
func receivePrologue(FpState interface{}, results []*pb.OuterStruct) {
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

	// Calculating final public key by multiplying them all together
	s.publicKey = *Multiply(0, len(s.keys), zkp.P, func(i int) *big.Int { return &s.keys[i] })

	log.Printf("Calculated public key: %v\n", s.publicKey.String())
}

func receiveRound1(FpState interface{}, results []*pb.OuterStruct) {
	s := getFpState(FpState)

	var round1 Round1

	// Store all received alphas and betas
	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].Data, &round1)
		if err != nil {
			log.Fatalf("Failed to unmarshal Round1.\n")
		}

		s.AlphasBetas[i] = new(AlphaBetaStruct)
		s.AlphasBetas[i].alphas =
			pb.ByteSliceToBigIntSlice(round1.Alphas)
		s.AlphasBetas[i].betas =
			pb.ByteSliceToBigIntSlice(round1.Betas)
	}
}

func receiveRound2(FpState interface{}, results []*pb.OuterStruct) {
	s := getFpState(FpState)

	var round2 Round2

	// Store all received alphas and betas
	for a := 0; a < len(results); a++ {
		if a == *id {
			continue
		}
		err := proto.Unmarshal(results[a].Data, &round2)
		if err != nil {
			log.Fatalf("Failed to unmarshal Round2.\n")
		}

		s.GammasDeltasAfterExponentiation[a] = make([]*GammaDeltaStruct, len(s.keys))

		for i := 0; i < len(s.keys); i++ { // len(s.keys) == len(results)
			s.GammasDeltasAfterExponentiation[a][i] = new(GammaDeltaStruct)
			s.GammasDeltasAfterExponentiation[a][i].gammas =
				pb.ByteSliceToBigIntSlice(round2.DoubleGammas[i].Gammas)
			s.GammasDeltasAfterExponentiation[a][i].deltas =
				pb.ByteSliceToBigIntSlice(round2.DoubleDeltas[i].Deltas)
		}

		log.Printf("[Round 2] Receiving ID %v: %v\n", a, s.GammasDeltasAfterExponentiation[a])
	}
}

func computePrologue(FpState interface{}) proto.Message {
	s := getFpState(FpState)

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

func computeRound1(FpState interface{}) proto.Message {
	s := getFpState(FpState)
	s.AlphasBetas = make([]*AlphaBetaStruct, len(s.keys))
	s.AlphasBetas[*id] = new(AlphaBetaStruct)

	log.Printf("Len: %v\n", len(s.keys))

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

		proofs = append(proofs, pb.CreateIsOneOfTwo(a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2))
	}

	log.Printf("Id: %v\n", *id)
	s.AlphasBetas[*id].alphas = alphasInts
	s.AlphasBetas[*id].betas = betasInts

	var pMinusOne big.Int
	pMinusOne.Sub(zkp.P, zkp.One)
	sumR.Mod(&sumR, &pMinusOne) // TODO I think. Fermat's little theorem

	gs := []big.Int{s.publicKey, *zkp.G}

	ts, r := zkp.DiscreteLogEquality(sumR, gs, *zkp.P, *zkp.Q)

	// create the proto Round1 structure
	return &Round1{
		Proofs: proofs,
		Proof:  pb.CreateDiscreteLogEquality(ts, r),
		Alphas: pb.BigIntSliceToByteSlice(alphasInts),
		Betas:  pb.BigIntSliceToByteSlice(betasInts),
	}
}

func computeRound2(FpState interface{}) proto.Message {
	s := getFpState(FpState)
	n := len(s.keys)

	proofs := make([]*DiscreteLogEqualityProofs, n)
	gammas := make([]*Gammas, n)
	deltas := make([]*Deltas, n)

	s.GammasDeltasBeforeExponentiation = make([]*GammaDeltaStruct, n)
	s.GammasDeltasAfterExponentiation = make([][]*GammaDeltaStruct, n)
	s.GammasDeltasAfterExponentiation[*id] = make([]*GammaDeltaStruct, n)

	getNumAlphas := func(x, y int) *big.Int {
		return &s.AlphasBetas[x].alphas[y]
	}
	getNumBetas := func(x, y int) *big.Int {
		return &s.AlphasBetas[x].betas[y]
	}

	// calculate all gammas and deltas before exponentiation
	// these are the same for everyone!
	// then calculate exponentiated values, one for each i and j.
	// Every person will send as i*j different exponentiated gammas
	// and i*j different exponentiated deltas!!!
	for j := 0; j < int(K); j++ {
		cachedValGammas := Round2ComputeInitialValue(n, int(K), j, zkp.P, getNumAlphas)
		cachedValDeltas := Round2ComputeInitialValue(n, int(K), j, zkp.P, getNumBetas)
		for i := 0; i < n; i++ {
			// initialize if necessary
			if j == 0 {
				s.GammasDeltasBeforeExponentiation[i] = new(GammaDeltaStruct)
				s.GammasDeltasAfterExponentiation[*id][i] = new(GammaDeltaStruct)
				proofs[i] = new(DiscreteLogEqualityProofs)
				gammas[i] = new(Gammas)
				deltas[i] = new(Deltas)
			}

			// compute unexponentiated gammas/deltas
			gamma := Round2ComputeOutcome(i, j, zkp.P, &cachedValGammas, getNumAlphas)
			delta := Round2ComputeOutcome(i, j, zkp.P, &cachedValDeltas, getNumBetas)

			s.GammasDeltasBeforeExponentiation[i].gammas =
				append(s.GammasDeltasBeforeExponentiation[i].gammas, gamma)
			s.GammasDeltasBeforeExponentiation[i].deltas =
				append(s.GammasDeltasBeforeExponentiation[i].deltas, delta)

			// now exponentiate to find the value we will publish to all!
			var mIJ big.Int
			mIJ.Rand(zkp.RandGen, zkp.Q)

			var gammaExp, deltaExp big.Int
			gammaExp.Exp(&gamma, &mIJ, zkp.P)
			deltaExp.Exp(&delta, &mIJ, zkp.P)

			// add exponentiated value to our exponentiated Gammas/Deltas struct
			s.GammasDeltasAfterExponentiation[*id][i].gammas =
				append(s.GammasDeltasAfterExponentiation[*id][i].gammas, gammaExp)
			s.GammasDeltasAfterExponentiation[*id][i].deltas =
				append(s.GammasDeltasAfterExponentiation[*id][i].deltas, deltaExp)

			// must prove that our exponentiated values have same exponent
			gs := []big.Int{gamma, delta}

			// now generate proof!
			ts, r := zkp.DiscreteLogEquality(mIJ, gs, *zkp.P, *zkp.Q)

			// and add to the list of proofs!
			proofs[i].Proofs = append(proofs[i].Proofs, pb.CreateDiscreteLogEquality(ts, r))
			// add the number manually
			gammas[i].Gammas = append(gammas[i].Gammas, gammaExp.Bytes())
			deltas[i].Deltas = append(deltas[i].Deltas, deltaExp.Bytes())

			log.Printf("Created gammaExp/deltaExp %v/%v with proof values %v, %v", gammaExp, deltaExp, ts, r)
		}

		// log.Printf("Going to send gammas/deltas: %v\n%v",
		// 	s.GammasDeltasBeforeExponentiation[*id].gammas,
		// 	s.GammasDeltasBeforeExponentiation[*id].deltas)
	}

	// TODO need to do this for EACH i, not just our own
	// TODO most places where *id is used, it is wrong

	log.Printf("[Round 2] Sending ID %v: %v\n", *id, s.GammasDeltasAfterExponentiation[*id])

	// TODO no....
	return &Round2{
		DoubleProofs: proofs,
		DoubleGammas: gammas,
		DoubleDeltas: deltas,
	}
}

// TODO seller needs to know shit

func computeRound3(FpState interface{}) proto.Message {
	// s := getFpState(FpState)
	// n := len(s.keys)

	return nil
}
