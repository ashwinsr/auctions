package main

import (
	"flag"
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

var K uint = 100

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

	AlphasBetas []*AlphaBetaStruct

	GammasDeltasBeforeExponentiation []*GammaDeltaStruct   // indices (i, j)
	GammasDeltasAfterExponentiation  [][]*GammaDeltaStruct // indices (a, i, j)

	PhisBeforeExponentiation [][]big.Int   // indices (i, j)
	PhisAfterExponentiation  [][][]big.Int // indices (a, i, j)

	sellerRound3 Round3
}

func main() {
	flag.Parse()

	myState := &FpState{}

	hosts, myID := lib.GetHostsAndID()
	*id = myID


	myAddr := hosts[*id]
	lib.Init(*id)

	fmt.Println("My address is: ", myAddr)
	fmt.Println("My ID is: ", *id)

	go lib.RunServer(myAddr)

	lib.InitClients(hosts, myAddr)

	var rounds []lib.Round
	
	if *id == 0 {
		// If seller
		rounds = []lib.Round{
			{computePrologue, checkPrologue, receivePrologue},
			{computeRound1, checkRound1, receiveRound1},
			{computeRound2, checkRound2, receiveRound2},
			{computeRound3, checkRound3, sellerReceiveRound3},
		}	
	} else {
		// If bidder
		rounds = []lib.Round{
			{computePrologue, checkPrologue, receivePrologue},
			{computeRound1, checkRound1, receiveRound1},
			{computeRound2, checkRound2, receiveRound2},
			{computeRound3, checkRound3, receiveRound3},
		}		
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

	// This checks if the bidder bid exactly one value:
	// Only one of the alphas should have Y as a factor, and therefore
	// dividing their product by Y gives us y^(sum of the r's).
	// Then multiplying all of the betas together gives us g^(sum of the r's).
	// Therefore we check that these two have the same exponent!

	yExpSumR := *Multiply(0, len(alphas), zkp.P, func(i int) *big.Int { return &alphas[i] })
	gExpSumR := *Multiply(0, len(betas), zkp.P, func(i int) *big.Int { return &betas[i] })

	// divide by Y
	YInv := new(big.Int).ModInverse(zkp.Y_Mill, zkp.P)
	yExpSumR.Mul(&yExpSumR, YInv)
	yExpSumR.Mod(&yExpSumR, zkp.P)

	bases := []big.Int{s.publicKey, *zkp.G}
	results := []big.Int{yExpSumR, gExpSumR}

	ts, r := pb.DestructDiscreteLogEquality(in.Proof)

	if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
		log.Fatalf("Received incorrect zero-knowledge proof for alphas/betas: bidder bid multiple values?")
	}

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

			// bases are their gammas and deltas before exponentiation!
			bases := []big.Int{
				s.GammasDeltasBeforeExponentiation[i].gammas[j],
				s.GammasDeltasBeforeExponentiation[i].deltas[j],
			}
			results := []big.Int{gammas[j], deltas[j]}
			log.Printf("Received gamma/delta %v/%v with proof values %v, %v, and bases %v",
				gammas[j], deltas[j], ts, r, bases)

			if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
				log.Fatalf("Received incorrect zero-knowledge proof for gamma/delta")
			}
		}
	}

	return
}

func checkRound3(state interface{}, result *pb.OuterStruct) (err error) {
	s := getFpState(state)
	var in Round3

	err = proto.Unmarshal(result.Data, &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal Round2.\n")
	}

	// TODO need error checking

	// if len(in.Gammas) != len(in.Deltas) || len(in.Proofs) != len(in.Deltas) || uint(len(in.Proofs)) != K {
	// 	log.Fatalf("Incorrect number of shit2: %v %v %v %v", len(in.Gammas), len(in.Deltas), len(in.Proofs), K)
	// }

	if len(in.DoublePhis) != len(in.DoubleProofs) ||
		len(in.DoubleProofs) != len(s.keys) {
		log.Fatalf("Incorrect number of outer shit2")
	}

	for i := 0; i < len(in.DoublePhis); i++ {
		if len(in.DoublePhis[i].Phis) != len(in.DoubleProofs[i].Proofs) ||
			len(in.DoubleProofs[i].Proofs) != int(K) {
			log.Fatalf("Incorrect number of inner shit2 %v %v\n",
				len(in.DoublePhis[i].Phis),
				len(in.DoubleProofs[i].Proofs))
		}

		phis := pb.ByteSliceToBigIntSlice(in.DoublePhis[i].Phis)

		for j := 0; j < len(in.DoublePhis[i].Phis); j++ {
			ts, r := pb.DestructDiscreteLogEquality(in.DoubleProofs[i].Proofs[j])

			// bases are their gammas and deltas before exponentiation!
			bases := []big.Int{
				s.PhisBeforeExponentiation[i][j],
				*zkp.G,
			}
			results := []big.Int{phis[j], s.keys[result.Clientid]}
			log.Printf("Received phi %v with proof values %v, %v, and bases %v",
				phis[j], ts, r, bases)

			if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
				log.Fatalf("Received incorrect zero-knowledge proof for phis")
			}
		}
	}

	return
}

// TODO decompose! Can be used in both millionaires and auction
func receivePrologue(FpState interface{}, results []*pb.OuterStruct) {
	s := getFpState(FpState)
	var key pb.Key

	s.keys = make([]big.Int, len(results))

	s.keys[*id] = s.myPublicKey

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
		s.keys[i] = k
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

func receiveRound3(FpState interface{}, results []*pb.OuterStruct) {
	s := getFpState(FpState)

	var round3 Round3

	// Store all received alphas and betas
	log.Printf("results round 3", len(results))
	for a := 0; a < len(results); a++ {
		if a == *id {
			continue
		}

		log.Printf("Received Clientid %v", results[a].Clientid)
		
		err := proto.Unmarshal(results[a].Data, &round3)
		if err != nil {
			log.Fatalf("Failed to unmarshal Round3.\n", results[a])
		}

		s.PhisAfterExponentiation[a] = make([][]big.Int, len(s.keys))

		for i := 0; i < len(s.keys); i++ { // len(s.keys) == len(results)
			s.PhisAfterExponentiation[a][i] =
				pb.ByteSliceToBigIntSlice(round3.DoublePhis[i].Phis)
		}

		log.Printf("[Round 3] Receiving ID %v: %v\n", a, s.PhisAfterExponentiation[a])
	}

	epilogue(s)
}

func sellerReceiveRound3(FpState interface{}, results []*pb.OuterStruct) {
	s := getFpState(FpState)

	var round3 Round3

	// Store all received alphas and betas
	log.Printf("Results Size: %v", len(results))
	for a := 0; a < len(results); a++ {
		if a == *id {
			continue
		}
		err := proto.Unmarshal(results[a].Data, &round3)
		if err != nil {
			log.Fatalf("Seller failed to unmarshal Round3.\n")
		}

		s.PhisAfterExponentiation[a] = make([][]big.Int, len(s.keys))

		for i := 0; i < len(s.keys); i++ { // len(s.keys) == len(results)
			s.PhisAfterExponentiation[a][i] =
				pb.ByteSliceToBigIntSlice(round3.DoublePhis[i].Phis)
		}

		log.Printf("[Round 3] Receiving ID %v: %v\n", a, s.PhisAfterExponentiation[a])
		log.Printf("Publishing Clientid", results[a].Clientid)
		log.Printf("Publishing Stepid", results[a].Stepid)
		log.Printf("Round 3", results[a].Data)

		lib.PublishAll(results[a])
	}

	r, _ := proto.Marshal(&s.sellerRound3)

	out := &pb.OuterStruct{
		Clientid: int32(*id),
		Stepid:   4,
		Data:     r,
	}

	lib.PublishAll(out)

	epilogue(s)
}

func computePrologue(FpState interface{}) (proto.Message, bool) {
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
	}, false
}

func computeRound1(FpState interface{}) (proto.Message, bool) {
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
		var alphaJ, betaJ, rJ, m big.Int

		rJ.Rand(zkp.RandGen, zkp.Q)
		sumR.Add(&sumR, &rJ)

		alphaJ.Exp(&s.publicKey, &rJ, zkp.P) // TODO mod P?

		if j == *bid {
			m.Set(zkp.Y_Mill)
			alphaJ.Mul(&alphaJ, zkp.Y_Mill)
			alphaJ.Mod(&alphaJ, zkp.P)
		} else {
			m.Set(zkp.One)
		}

		// calculate beta_j
		betaJ.Exp(zkp.G, &rJ, zkp.P)

		alphasInts = append(alphasInts, alphaJ)
		betasInts = append(betasInts, betaJ)

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
	}, false
}

func computeRound2(FpState interface{}) (proto.Message, bool) {
	s := getFpState(FpState)
	n := len(s.keys)

	proofs := make([]*DiscreteLogEqualityProofs, n)
	gammas := make([]*Gammas, n)
	deltas := make([]*Deltas, n)

	s.GammasDeltasBeforeExponentiation = make([]*GammaDeltaStruct, n)
	s.GammasDeltasAfterExponentiation = make([][]*GammaDeltaStruct, n)
	s.GammasDeltasAfterExponentiation[*id] = make([]*GammaDeltaStruct, n)

	getNumAlphas := func(x, y int) *big.Int {
		log.Printf("[Round 2] AlphasBetas[%v].alphas[%v] = %v\n", x, y, s.AlphasBetas[x].alphas[y])
		return &s.AlphasBetas[x].alphas[y]
	}
	getNumBetas := func(x, y int) *big.Int {
		log.Printf("[Round 2] AlphasBetas[%v].betas[%v] = %v\n", x, y, s.AlphasBetas[x].betas[y])
		return &s.AlphasBetas[x].betas[y]
	}

	// calculate all gammas and deltas before exponentiation
	// these are the same for everyone!
	// then calculate exponentiated values, one for each i and j.
	// Every person will send as i*j different exponentiated gammas
	// and i*j different exponentiated deltas!!!
	for j := 0; j < int(K); j++ {
		log.Printf("[Round 2] %v-th outer loop\n", j)
		cachedValGamma := Round2ComputeInitialValue(n, int(K), j, zkp.P, getNumAlphas)
		cachedValDelta := Round2ComputeInitialValue(n, int(K), j, zkp.P, getNumBetas)
		log.Printf("[Round 2] Cached val gamma: %v, Cached val delta: %v", cachedValGamma, cachedValDelta)
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
			log.Printf("[Round 2] %v-th inner loop\n", i)
			gamma := Round2ComputeOutcome(i, j, zkp.P, &cachedValGamma, getNumAlphas)
			delta := Round2ComputeOutcome(i, j, zkp.P, &cachedValDelta, getNumBetas)
			log.Printf("Finished computing non-cached value\n")

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

			log.Printf("Created gammaExp/deltaExp %v/%v with proof values %v, %v, and bases %v",
				gammaExp, deltaExp, ts, r, gs)
		}

		// log.Printf("Going to send gammas/deltas: %v\n%v",
		// 	s.GammasDeltasBeforeExponentiation[*id].gammas,
		// 	s.GammasDeltasBeforeExponentiation[*id].deltas)
	}

	log.Printf("[Round 2] Sending ID %v: %v\n", *id, s.GammasDeltasAfterExponentiation[*id])

	// TODO no....
	return &Round2{
		DoubleProofs: proofs,
		DoubleGammas: gammas,
		DoubleDeltas: deltas,
	}, false
}

func computeRound3(FpState interface{}) (proto.Message, bool) {
	s := getFpState(FpState)
	n := len(s.keys)

	var doublePhis []*Phis
	var proofs []*DiscreteLogEqualityProofs

	s.PhisAfterExponentiation = make([][][]big.Int, n)

	for i := 0; i < n; i++ {
		s.PhisBeforeExponentiation =
			append(s.PhisBeforeExponentiation, nil)
		s.PhisAfterExponentiation[*id] =
			append(s.PhisAfterExponentiation[*id], nil)

		proofs = append(proofs, &DiscreteLogEqualityProofs{})

		for j := 0; j < int(K); j++ {
			phi := Multiply(0, n, zkp.P, func(h int) *big.Int {
				return &s.GammasDeltasAfterExponentiation[h][i].deltas[j]
			})

			var phiExp big.Int
			phiExp.Exp(phi, &s.myPrivateKey, zkp.P)

			s.PhisBeforeExponentiation[i] =
				append(s.PhisBeforeExponentiation[i], *phi)

			s.PhisAfterExponentiation[*id][i] =
				append(s.PhisAfterExponentiation[*id][i], phiExp)

			// must prove that our exponentiated phi has same exponent as our public key portion
			gs := []big.Int{*phi, *zkp.G}

			// now generate proof!
			ts, r := zkp.DiscreteLogEquality(s.myPrivateKey, gs, *zkp.P, *zkp.Q)

			proofs[i].Proofs = append(proofs[i].Proofs, pb.CreateDiscreteLogEquality(ts, r))
		}

		log.Printf("Hullo: %v %v\n", i, len(s.PhisAfterExponentiation[*id][i]))

		doublePhis = append(doublePhis, &Phis{
			Phis: pb.BigIntSliceToByteSlice(s.PhisAfterExponentiation[*id][i]),
		})
	}

	var round3 Round3
	round3 = Round3{
		DoublePhis:   doublePhis,
		DoubleProofs: proofs,
	}
	if *id == 0 {
		s.sellerRound3 = round3	
	}
	return &round3, true
}

func epilogue(s *FpState) {
	n := len(s.keys)
	for a := 0; a < n; a++ {
		for j := 0; j < int(K); j++ {
			numerator := Multiply(0, n, zkp.P, func(i int) *big.Int {
				return &s.GammasDeltasAfterExponentiation[i][a].gammas[j]
			})

			denominator := Multiply(0, n, zkp.P, func(i int) *big.Int {
				return &s.PhisAfterExponentiation[i][a][j]
			})

			//log.Printf("Numerator: %v, Denominator: %v", numerator, denominator)

			denominator.ModInverse(denominator, zkp.P)

			var vAJ big.Int
			vAJ.Mul(numerator, denominator)
			vAJ.Mod(&vAJ, zkp.P)

			if vAJ.Cmp(zkp.One) == 0 {
			    if (a == *id) {
					log.Printf("I won at selling price %v!", j)
				} else {
				    log.Printf("I did not win. ID %v won at selling price %v.", a, j)
				}
			}
		}
	}

	log.Fatalf("Done")
}
