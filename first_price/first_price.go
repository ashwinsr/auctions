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

var K uint = 27

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

	AlphasBetas                      []*AlphaBetaStruct // TODO Akshay remember to initialize
	GammasDeltasBeforeExponentiation []*GammaDeltaStruct
	GammasDeltasAfterExponentiation  []*GammaDeltaStruct
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
		log.Fatalf("Incorrect number of shit")
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

	if len(in.Gammas) != len(in.Deltas) || len(in.Proofs) != len(in.Deltas) || uint(len(in.Proofs)) != K {
		log.Fatalf("Incorrect number of shit")
	}

	gammas := pb.ByteSliceToBigIntSlice(in.Gammas)
	deltas := pb.ByteSliceToBigIntSlice(in.Deltas)

	for i := 0; i < len(in.Gammas); i++ {
		ts, r := pb.DestructDiscreteLogEquality(in.Proofs[i])

		// bases are their gammas and deltas before exponentiation!
		bases := []big.Int{
			s.GammasDeltasBeforeExponentiation[result.Clientid].gammas[i],
			s.GammasDeltasBeforeExponentiation[result.Clientid].deltas[i],
		}
		results := []big.Int{gammas[i], deltas[i]}

		if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
			log.Fatalf("Received incorrect zero-knowledge proof for alpha/beta")
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

	// Calculating final public key
	// TODO SHOULD THIS BE MOD P? Probably doesn't matter, but just for computational practicality
	s.publicKey.Set(zkp.One)
	for _, key := range s.keys {
		s.publicKey.Mul(&s.publicKey, &key)
		s.publicKey.Mod(&s.publicKey, zkp.P)
	}

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

		s.AlphasBetas[results[i].Clientid].alphas =
			pb.ByteSliceToBigIntSlice(round1.Alphas)
		s.AlphasBetas[results[i].Clientid].betas =
			pb.ByteSliceToBigIntSlice(round1.Betas)
	}
}

func receiveRound2(FpState interface{}, results []*pb.OuterStruct) {
	s := getFpState(FpState)

	var round2 Round2

	// Store all received alphas and betas
	for i := 0; i < len(results); i++ {
		if i == *id {
			continue
		}
		err := proto.Unmarshal(results[i].Data, &round2)
		if err != nil {
			log.Fatalf("Failed to unmarshal Round2.\n")
		}

		s.GammasDeltasAfterExponentiation[results[i].Clientid].gammas =
			pb.ByteSliceToBigIntSlice(round2.Gammas)
		s.GammasDeltasAfterExponentiation[results[i].Clientid].deltas =
			pb.ByteSliceToBigIntSlice(round2.Deltas)
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

	s.AlphasBetas[*id].alphas = alphasInts
	s.AlphasBetas[*id].betas = betasInts

	sumR.Mod(&sumR, zkp.Z) // TODO Akshay what is Z?

	var gs []big.Int
	gs = append(gs, s.publicKey)
	gs = append(gs, *zkp.G)

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
	s.GammasDeltasBeforeExponentiation = make([]*GammaDeltaStruct, n)
	s.GammasDeltasAfterExponentiation = make([]*GammaDeltaStruct, n)

	var proofs []*pb.DiscreteLogEquality

	for j := 0; j < int(K); j++ {
		var mJ big.Int
		mJ.Rand(zkp.RandGen, zkp.Q)

		gammaJExponentiated, gammaJs :=
			ComputeOutcome(*id, j, n, int(K), &mJ, zkp.P, func(x, y int) *big.Int {
				return &s.AlphasBetas[x].alphas[y]
			})

		deltaJExponentiated, deltaJs :=
			ComputeOutcome(*id, j, n, int(K), &mJ, zkp.P, func(x, y int) *big.Int {
				return &s.AlphasBetas[x].betas[y]
			})

		// add all calculated values to state

		// we have calculated the j-th unexponentiated value for all persons i
		// so add the j-th value to each person i's unexponentiated struct
		for i := 0; i < n; i++ {
			s.GammasDeltasBeforeExponentiation[i].gammas =
				append(s.GammasDeltasBeforeExponentiation[i].gammas, gammaJs[i])

			s.GammasDeltasBeforeExponentiation[i].deltas =
				append(s.GammasDeltasBeforeExponentiation[i].deltas, deltaJs[i])
		}

		// only have our calculated values for after exponentiation.
		// will receive others' calculated values in the receiveRound2 function
		s.GammasDeltasAfterExponentiation[*id].gammas =
			append(s.GammasDeltasAfterExponentiation[*id].gammas, gammaJExponentiated)

		s.GammasDeltasAfterExponentiation[*id].deltas =
			append(s.GammasDeltasAfterExponentiation[*id].deltas, deltaJExponentiated)

		// must prove that our exponentiated values have same exponent
		gs := []big.Int{gammaJs[*id], deltaJs[*id]}

		// now generate proof!
		ts, r := zkp.DiscreteLogEquality(mJ, gs, *zkp.P, *zkp.Q)

		proofs = append(proofs, pb.CreateDiscreteLogEquality(ts, r))
	}

	return &Round2{
		Proofs: proofs,
		Gammas: pb.BigIntSliceToByteSlice(s.GammasDeltasAfterExponentiation[*id].gammas),
		Deltas: pb.BigIntSliceToByteSlice(s.GammasDeltasAfterExponentiation[*id].deltas),
	}
}
