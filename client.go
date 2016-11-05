package main

import (
	"encoding/json"
	"flag"
	// "fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/ashwinsr/auctions/millionaire"
	"github.com/ashwinsr/auctions/pb"
	"github.com/ashwinsr/auctions/zkp"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"golang.org/x/net/context"

	// "net/http"
	_ "net/http/pprof"
)

// TODO debugging
// func init() {
//   go func() {
//     log.Println(http.ListenAndServe("localhost:6060", nil))
//   }()
// }

// Need to convert to using command line options for a lot of these

// Note we have no fault tolerance in these protocols.

// keeps state
type state struct {
	myPrivateKey big.Int
	myPublicKey  big.Int
	keys         []big.Int
	publicKey    big.Int

	// TODO millionaire specific
	myAlphasBetas                 *AlphaBetaStruct
	theirAlphasBetas              *AlphaBetaStruct
	myGammasDeltas                *millionaire.GammaDeltaStruct
	theirGammasDeltas             *millionaire.GammaDeltaStruct
	myExponentiatedGammasDeltas   *millionaire.GammaDeltaStruct
	theirExponentiatedGammasDelta *millionaire.GammaDeltaStruct
	phisBeforeExponentiation      *millionaire.PhiStruct
	myPhis                        *millionaire.PhiStruct
	theirPhis                     *millionaire.PhiStruct
}

// TODO don't be such a complete piece of shit
var myState *state

// channels for each round
/*
 * These are here so that protobuf data, if received before we have moved
 * onto the next round, just wait in the channel until we are ready.
 */
var (
	clients []pb.ZKPAuctionClient
	keyChan chan big.Int = make(chan big.Int) // TODO bother with buffer?

	// TODO millionaire specific
	alphaBetaChan                 chan *AlphaBetaStruct              = make(chan *AlphaBetaStruct)
	exponentiatedGammasDeltasChan chan *millionaire.GammaDeltaStruct = make(chan *millionaire.GammaDeltaStruct)
	phiChan                       chan *millionaire.PhiStruct        = make(chan *millionaire.PhiStruct)
)

// TODO millionaire specific
type AlphaBetaStruct struct {
	alphas, betas []big.Int
}

var (
	hostsFileName = flag.String("hosts", "hosts.json", "JSON file with lists of hosts to communicate with")
	id            = flag.Int("id", -1, "ID")

	// TODO millionaire specific
	bid = flag.Uint("bid", 0, "Amount of money")
)

// server is used to implement pb.ZKPAuctionServer
type server struct{}

// SendKey implements pb.ZKPAuctionServer
func (s *server) SendKey(ctx context.Context, in *pb.Key) (*google_protobuf.Empty, error) {
	var key, t, r big.Int
	key.SetBytes(in.Key) // TODO this how you access Key? Or GetKey()
	t.SetBytes(in.GetProof().T)
	r.SetBytes(in.GetProof().R)

	log.Printf("Received key: %v\n", key)

	if err := zkp.CheckDiscreteLogKnowledgeProof(*zkp.G, key, t, r, *zkp.P, *zkp.Q); err != nil {
		log.Fatalf("Received incorrect zero-knowledge proof. Key=%v, t=%v, r=%v", key, t, r)
	}

	// put key into keyChan in a goroutine, as we want to return as soon as possible
	go func() {
		keyChan <- key
	}()

	return &google_protobuf.Empty{}, nil
}

// TODO millionaire specific
// MillionaireAlphaBeta implements pb.ZKPAuctionServer
func (s *server) MillionaireAlphaBeta(ctx context.Context, in *pb.AlphaBeta) (*google_protobuf.Empty, error) {
	if len(in.Alphas) != len(in.Betas) || len(in.Proofs) != len(in.Betas) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Fatalf("Incorrect number of shit")
	}

	var abs AlphaBetaStruct

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
			*zkp.G, myState.publicKey, *zkp.Y_Mill); err != nil {
			log.Fatalf("Received incorrect zero-knowledge proof for alpha/beta")
		}
		// TODO change to pass protobuf structs
		abs.alphas = append(abs.alphas, alpha)
		abs.betas = append(abs.betas, beta)
	}

	// TODO debugging
	log.Printf("Received Alphas: %v", abs.alphas)
	log.Printf("Received Betas: %v", abs.betas)

	go func() {
		alphaBetaChan <- &abs
	}()

	return &google_protobuf.Empty{}, nil
}

func (s *server) MillionaireGammaDelta1(ctx context.Context, in *pb.MixedOutput) (*google_protobuf.Empty, error) {
	return &google_protobuf.Empty{}, nil
}
func (s *server) MillionaireGammaDelta2(ctx context.Context, in *pb.MixedOutput) (*google_protobuf.Empty, error) {
	return &google_protobuf.Empty{}, nil
}
func (s *server) MillionaireRandomizeOutput(ctx context.Context, in *pb.RandomizedOutput) (*google_protobuf.Empty, error) {
	if len(in.Gammas) != len(in.Deltas) || len(in.Proofs) != len(in.Deltas) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Fatalf("Incorrect number of shit4")
	}

	var gds millionaire.GammaDeltaStruct

	for j := 0; j < len(in.Gammas); j++ {
		var gamma, delta big.Int
		gamma.SetBytes(in.Gammas[j])
		delta.SetBytes(in.Deltas[j])

		gds.Gammas = append(gds.Gammas, gamma)
		gds.Deltas = append(gds.Deltas, delta)

		var bases, results, ts []big.Int
		// TODO myGammasDeltas for now
		bases = append(bases, myState.myGammasDeltas.Gammas[j])
		bases = append(bases, myState.myGammasDeltas.Deltas[j])
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

		log.Printf("Checking proof.\nBases=%v\nResults=%v\nTs=%vn,R=%v\n", bases, results, ts, r)
		if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
			log.Fatalf("Received incorrect zero-knowledge proof for exponentiated gammas/deltas")
		}
	}

	// TODO debugging
	log.Printf("Received Exponentiated gammas: %v", gds.Gammas)
	log.Printf("Received Exponentiated deltas: %v", gds.Deltas)

	go func() {
		exponentiatedGammasDeltasChan <- &gds
	}()
	return &google_protobuf.Empty{}, nil
}

func (s *server) MillionaireDecryptionInfo(ctx context.Context, in *pb.DecryptionInfo) (*google_protobuf.Empty, error) {
	if len(in.Phis) != len(in.Proofs) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Fatalf("Incorrect number of shit5")
	}

	var phis millionaire.PhiStruct

	for j := 0; j < len(in.Phis); j++ {
		var phi big.Int
		phi.SetBytes(in.Phis[j])

		phis.Phis = append(phis.Phis, phis)

		var bases, results, ts []big.Int
		// proof equality of logarithms of the received phi and their public key
		bases = append(bases, myState.myPhisBeforeExponentiation.Phis[i])
		bases = append(bases, *zkp.G)
		results = append(results, phi)
		results = append(results, myState.keys[1]) // their public key

		// set proof values
		var r big.Int
		r.SetBytes(in.Proofs[j].R)
		for _, t := range in.Proofs[j].Ts {
			var t_temp big.Int
			t_temp.SetBytes(t)
			ts = append(ts, t_temp)
		}

		log.Printf("Checking proof.\nBases=%v\nResults=%v\nTs=%vn,R=%v\n", bases, results, ts, r)
		if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
			log.Fatalf("Received incorrect zero-knowledge proof for phis")
		}
	}

	// TODO debugging
	log.Printf("Received Phis: %v")

	go func() {
		phiChan <- &phis
	}()
	return &google_protobuf.Empty{}, nil
}

// Listens for connections; meant to be run in a goroutine
func runServer(localHost string) {
	lis, err := net.Listen("tcp", localHost)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterZKPAuctionServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func getHosts() []string {
	hostsFile, err := os.Open(*hostsFileName)
	if err != nil {
		log.Fatalf("Error opening hosts file: %v", err)
	}

	var hosts struct {
		Hosts []string `json:"hosts"`
	}

	if err = json.NewDecoder(hostsFile).Decode(&hosts); err != nil {
		log.Fatalf("Error opening hosts file: %v", err)
	}

	return hosts.Hosts
}

func initClients(hosts []string, myAddr string) {
	// generate clients sequentially, not so bad
	for _, host := range hosts {
		if host == myAddr {
			continue
		}
		// Set up a connection to the server.
		conn, err := grpc.Dial(host, grpc.WithInsecure(), grpc.WithBackoffMaxDelay(1*time.Second), grpc.WithBlock())
		if err != nil {
			log.Fatalf("Did not connect (to host %v): %v", host, err)
		}
		// defer conn.Close() TODO: This needs to happen at somepoint, but not here
		c := pb.NewZKPAuctionClient(conn)

		clients = append(clients, c)
	}

	log.Println("Finishing initializing clients")
}

func main() {
	flag.Parse()

	myState = &state{}

	hosts := getHosts()
	myAddr := hosts[*id]

	go runServer(myAddr)

	initClients(hosts, myAddr)

	myState.keyDistribution()

	// TODO millionaire specific shit
	myState.millionaire_AlphaBetaDistribute()
	myState.millionaire_MixOutput1()
	myState.millionaire_MixOutput2()
	myState.millionaire_RandomizeOutput()

	// TODO do this better
	for {
	}
}

/*
 * 1. Generates a private/public key pair
 * 2. Generates zero-knowledge-proof of private key
 * 3. Publishes the public key with zero-knowledge proof of private key
 * 4. Puts our own public key in state.keys
 * 5. Receives n public keys from keyChan, puts them in state.keys
 * 6. Calculates the final public key, and stores into state.
 */
func (s *state) keyDistribution() {
	log.Println("Beginning key distribution")

	// Generate private key
	s.myPrivateKey.Rand(zkp.RandGen, zkp.Q)
	// Calculate public key
	s.myPublicKey.Exp(zkp.G, &s.myPrivateKey, zkp.P)

	log.Printf("My public key: %v\n", s.myPublicKey)

	// Generate zkp of private key
	t, r := zkp.DiscreteLogKnowledge(s.myPrivateKey, *zkp.G, *zkp.P, *zkp.Q)
	// Create proto structure of zkp
	zkpPrivKey := &pb.DiscreteLogKnowledge{T: t.Bytes(), R: r.Bytes()}
	log.Printf("Sending t=%v, r=%v", t, r)

	// Publish public key to all clients
	for _, client := range clients {
		log.Println("Sending key to client...")
		go func() {
			// Needs to be a goroutine because otherwise we block waiting for a response
			_, err := client.SendKey(context.Background(),
				&pb.Key{
					Key:   s.myPublicKey.Bytes(),
					Proof: zkpPrivKey,
				})
			if err != nil {
				log.Fatalf("Error on sending key: %v", err)
			}
		}()
	}

	s.keys = append(s.keys, s.myPublicKey)

	// Wait for public keys of all other clients
	// TODO error handling
	for i := 0; i < len(clients); i++ {
		s.keys = append(s.keys, <-keyChan)
	}

	log.Printf("Keys: %v", s.keys)

	// Calculating final public key
	// TODO SHOULD THIS BE MOD P? Probably doesn't matter, but just for computational practicality
	s.publicKey.Set(zkp.One)
	for _, key := range s.keys {
		s.publicKey.Mul(&s.publicKey, &key)
	}
	s.publicKey.Mod(&s.publicKey, zkp.P)
}

func (s *state) millionaire_AlphaBetaDistribute() {
	// Publish alphas and betas to all of the clients

	var alphas, betas [][]byte
	var alphasInts, betasInts []big.Int

	var proofs []*pb.EqualsOneOfTwo

	var j uint
	for j = 0; j < zkp.K_Mill; j++ {
		var alphaJ, betaJ, rJ big.Int
		rJ.Rand(zkp.RandGen, zkp.Q)

		// get the j-th bit of bid
		Bij := (((*bid) >> j) & 1)

		// calculate alpha_j
		log.Printf("Public key: %v, Rj: %v, P: %v\n", s.publicKey, rJ, *zkp.P)
		alphaJ.Exp(&s.publicKey, &rJ, zkp.P) // TODO mod P?
		if Bij == 1 {
			alphaJ.Mul(&alphaJ, zkp.Y_Mill)
			alphaJ.Mod(&alphaJ, zkp.P)
		}

		// calculate beta_j
		betaJ.Exp(zkp.G, &rJ, zkp.P)

		log.Printf("alphaJ: %v\n", alphaJ)
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

		if err := zkp.CheckEncryptedValueIsOneOfTwo(alphaJ, betaJ, *zkp.P, *zkp.Q,
			a_1, a_2, b_1, b_2, d_1, d_2, r_1, r_2,
			*zkp.G, myState.publicKey, *zkp.Y_Mill); err != nil {
			log.Fatalf("WE ARE SENDING AN INCORRECT FUCKING PROOF")
		}

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

	for _, client := range clients {
		log.Println("Sending alpha, beta to client...")
		log.Printf("Sending alphas: %v\n", alphas)
		log.Printf("Sending betas: %v\n", betas)
		go func() {
			_, err := client.MillionaireAlphaBeta(context.Background(),
				&pb.AlphaBeta{
					Alphas: alphas,
					Betas:  betas,
					Proofs: proofs,
				})
			if err != nil {
				log.Fatalf("Error on sending alpha, beta: %v", err)
			}
		}()
	}

	s.myAlphasBetas = &AlphaBetaStruct{
		alphas: alphasInts,
		betas:  betasInts,
	}

	// Wait for alphas and betas of other client
	// TODO len should just be 1
	// TODO error handling
	for i := 0; i < len(clients); i++ {
		s.theirAlphasBetas = <-alphaBetaChan
	}
}

func (s *state) millionaire_MixOutput1() {
	// mostly a no-op just calculate (gamma, delta)
	gds := millionaire.MillionaireCalculateGammaDelta(s.myAlphasBetas.alphas, s.theirAlphasBetas.alphas,
		s.myAlphasBetas.betas, s.theirAlphasBetas.betas, *zkp.Y_Mill, *zkp.P)
	// TODO for now just set both
	s.myGammasDeltas = gds
	s.theirGammasDeltas = gds
}

func (s *state) millionaire_MixOutput2() {
	// no-op for now
}

// Takes gamme and delta to a random exponent, proves the equality of the exponent (logarithm)
func (s *state) millionaire_RandomizeOutput() {
	log.Println("Beginning random exponentiation")

	var proofs []*pb.DiscreteLogEquality

	var gammas, deltas [][]byte

	s.myExponentiatedGammasDeltas = new(millionaire.GammaDeltaStruct)

	// compute exponentiated gamma and delta
	// TODO for now myGammasDeltas
	for i := 0; i < len(s.myGammasDeltas.Gammas); i++ {
		log.Println("Beginning random exponentiation2")

		// for the protobuf struct
		gammas = append(gammas, s.myGammasDeltas.Gammas[i].Bytes())
		deltas = append(deltas, s.myGammasDeltas.Deltas[i].Bytes())

		// this is our random exponent
		var m big.Int
		m.Rand(zkp.RandGen, zkp.Q)

		var newGamma, newDelta big.Int
		newGamma.Exp(&s.myGammasDeltas.Gammas[i], &m, zkp.P)
		newDelta.Exp(&s.myGammasDeltas.Deltas[i], &m, zkp.P)
		log.Println("Beginning random exponentiation3")

		s.myExponentiatedGammasDeltas.Gammas = append(
			s.myExponentiatedGammasDeltas.Gammas, newGamma)

		s.myExponentiatedGammasDeltas.Deltas = append(
			s.myExponentiatedGammasDeltas.Deltas, newDelta)

		// to pass the bases to the zkp generator
		var gs []big.Int
		gs = append(gs, s.myGammasDeltas.Gammas[i])
		gs = append(gs, s.myGammasDeltas.Deltas[i])
		log.Println("Beginning random exponentiation4")

		// create proof and add it to proof list
		ts, r := zkp.DiscreteLogEquality(m, gs, *zkp.P, *zkp.Q)
		log.Printf("Creating proof.\nBases=%v\nExponent=%v\nTs=%vn,R=%v\n", gs, m, ts, r)

		log.Println("Beginning random exponentiation5")
		var proof pb.DiscreteLogEquality
		for _, t := range ts {
			proof.Ts = append(proof.Ts, t.Bytes())
		}

		log.Println("Beginning random exponentiation6")
		proof.R = r.Bytes()
		proofs = append(proofs, &proof)

		log.Println("Beginning random exponentiation7")
	}

	// Publish public key to all clients
	for _, client := range clients {
		log.Println("Sending exponentiated gammas/deltas...")
		go func() {
			// Needs to be a goroutine because otherwise we block waiting for a response
			_, err := client.MillionaireRandomizeOutput(context.Background(),
				&pb.RandomizedOutput{
					Gammas: gammas,
					Deltas: deltas,
					Proofs: proofs,
				})
			if err != nil {
				log.Fatalf("Error on sending exponentiated gammas/deltas: %v", err)
			}
		}()
	}

	log.Println("Beginning random exponentiation8")

	// Wait for gammas/deltas of all other clients (should be just 1 for millionaire)
	// TODO error handling
	for i := 0; i < len(clients); i++ {
		s.theirExponentiatedGammasDelta = <-exponentiatedGammasDeltasChan
	}

	log.Println("Beginning random exponentiation9")

	log.Printf("Received exponentiated gammas/deltas %v", s.theirExponentiatedGammasDelta)
	// TODO calcualte the final shit
}

// Calculates phis in order to decrypt them
func (s *state) millionaire_Decryption() {
	log.Println("Beginning decryption")

	var proofs []*pb.DiscreteLogEquality

	var phis [][]byte

	s.myPhis = new(millionaire.PhisStruct)
	s.phisBeforeExponentiation = new(millionaire.PhiStruct)

	// compute exponentiated gamma and delta
	// TODO for now myGammasDeltas
	for i := 0; i < len(s.myPhis.Phis); i++ {
		// calculate phi
		var phi, phi2 big.Int
		phi.Mul(s.myExponentiatedGammasDeltas.Deltas[i], s.theirExponentiatedGammasDelta.Deltas[i])
		phi.Mod(&phi, zkp.P)
		// before exponentiating, add it to our list for checking the ZKP
		phi2.Set(phi)
		s.phisBeforeExponentiation.Phis = append(s.phisBeforeExponentiation.Phis, phi2)
		phi.Exp(&phi, &s.myPrivateKey, zkp.P)
		s.myPhis.Phis = append(s.phisBeforeExponentiation.Phis, phi)

		// for the protobuf struct
		phis = append(phis, phi.Bytes())

		// to pass the bases to the zkp generator
		var gs []big.Int
		gs = append(gs, s.phi2)
		gs = append(gs, *zkp.G)

		// create proof and add it to proof list
		ts, r := zkp.DiscreteLogEquality(s.myPrivateKey, gs, *zkp.P, *zkp.Q)
		log.Printf("Creating proof.\nBases=%v\nExponent=%v\nTs=%vn,R=%v\n", gs, m, ts, r)

		var proof pb.DiscreteLogEquality
		for _, t := range ts {
			proof.Ts = append(proof.Ts, t.Bytes())
		}

		proof.R = r.Bytes()
		proofs = append(proofs, &proof)
	}

	// Publish public key to all clients
	for _, client := range clients {
		log.Println("Sending exponentiated phis...")
		go func() {
			// Needs to be a goroutine because otherwise we block waiting for a response
			_, err := client.MillionaireDecryptInfo(context.Background(),
				&pb.DecryptInfo{
					Phis:   phis,
					Proofs: proofs,
				})
			if err != nil {
				log.Fatalf("Error on sending phis: %v", err)
			}
		}()
	}

	// Wait for gammas/deltas of all other clients (should be just 1 for millionaire)
	// TODO error handling
	for i := 0; i < len(clients); i++ {
		s.theirPhis = <-phiChan
	}

	log.Printf("Received phis %v", s.theirPhis)
	// TODO calcualte the final shit (division + which one is bigger)
}