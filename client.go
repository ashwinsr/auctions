package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/ashwinsr/auctions/millionaire"
	"github.com/ashwinsr/auctions/pb"
	"github.com/ashwinsr/auctions/zkp"
	"github.com/golang/protobuf/proto"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"

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
	currRound    int

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

	// Publish
	isReady      chan struct{}
	receivedChan chan pb.Result = make(chan pb.Result)
	checkedChan  chan pb.Result = make(chan pb.Result)

	canReceiveKeys chan struct{}

	// TODO millionaire specific
	alphaBetaChan                 chan *AlphaBetaStruct = make(chan *AlphaBetaStruct)
	canReceiveAlphaBeta           chan struct{}
	exponentiatedGammasDeltasChan chan *millionaire.GammaDeltaStruct = make(chan *millionaire.GammaDeltaStruct)
	canReceiveGammasDeltas        chan struct{}
	phiChan                       chan *millionaire.PhiStruct = make(chan *millionaire.PhiStruct)
	canReceivePhis                chan struct{}
)

// TODO millionaire specific
// TODO delete
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

func (s *server) Publish(ctx context.Context, in *pb.OuterStruct) (*google_protobuf.Empty, error) {
	go func() {
		// Wait until we are ready
		<-isReady

		receivedChan <- *in
	}()

	return &google_protobuf.Empty{}, nil
}

// TODO delete all these gRPC functions
func (s *server) MillionaireGammaDelta1(ctx context.Context, in *pb.MixedOutput) (*google_protobuf.Empty, error) {
	return &google_protobuf.Empty{}, nil
}
func (s *server) MillionaireGammaDelta2(ctx context.Context, in *pb.MixedOutput) (*google_protobuf.Empty, error) {
	return &google_protobuf.Empty{}, nil
}
func (s *server) MillionaireRandomizeOutput(ctx context.Context, in *pb.RandomizedOutput) (*google_protobuf.Empty, error) {
	go func() {
		// wait until we can receive gammas and deltas
		<-canReceiveGammasDeltas

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

			// log.Printf("RECEIVE: Checking proof.\nBases=%v\nResults=%v\nTs=%vn,R=%v\n", bases, results, ts, r)
			if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
				log.Fatalf("Received incorrect zero-knowledge proof for exponentiated gammas/deltas")
			}
		}

		// TODO debugging
		// log.Printf("Received Exponentiated gammas: %v", gds.Gammas)
		// log.Printf("Received Exponentiated deltas: %v", gds.Deltas)

		// go func() {
		exponentiatedGammasDeltasChan <- &gds
		// }()
	}()

	return &google_protobuf.Empty{}, nil
}

func (s *server) MillionaireDecryptionInfo(ctx context.Context, in *pb.DecryptionInfo) (*google_protobuf.Empty, error) {
	go func() {
		// wait until we can receive phis
		<-canReceivePhis

		if len(in.Phis) != len(in.Proofs) || uint(len(in.Proofs)) != zkp.K_Mill {
			log.Printf("len of phis=%v, len of proofs=%v, k=%v\n", len(in.Phis), uint(len(in.Proofs)), zkp.K_Mill)
			log.Fatalf("Incorrect number of shit5")
		}

		var phis millionaire.PhiStruct

		for j := 0; j < len(in.Phis); j++ {
			var phi big.Int
			phi.SetBytes(in.Phis[j])

			phis.Phis = append(phis.Phis, phi)

			var bases, results, ts []big.Int
			// proof equality of logarithms of the received phi and their public key
			bases = append(bases, myState.phisBeforeExponentiation.Phis[j])
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

			// log.Printf("Checking proof.\nBases=%v\nResults=%v\nTs=%vn,R=%v\n", bases, results, ts, r)
			if err := zkp.CheckDiscreteLogEqualityProof(bases, results, ts, r, *zkp.P, *zkp.Q); err != nil {
				log.Fatalf("Received incorrect zero-knowledge proof for phis")
			}
		}

		// TODO debugging
		// log.Printf("Received Phis: %v", phis)

		// go func() {
		phiChan <- &phis
		// }()
	}()

	return &google_protobuf.Empty{}, nil
}

// Listens for connections; meant to be run in a goroutine
func runServer(localHost string) {
	lis, err := net.Listen("tcp", localHost)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Get options
	var opts []grpc.ServerOption
	cert := getServerCertificate()
	opts = []grpc.ServerOption{grpc.Creds(cert)}

	s := grpc.NewServer(opts...)
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

func getClientCertificate() credentials.TransportCredentials {
	certFile := fmt.Sprintf("certs/%v.pem", *id)
	cert, err := credentials.NewClientTLSFromFile(certFile, "")
	if err != nil {
		log.Fatalf("Could not load client TLS certificate: %v", err)
	}

	return cert
}

func getServerCertificate() credentials.TransportCredentials {
	certFile := fmt.Sprintf("certs/%v.pem", *id)
	keyFile := fmt.Sprintf("certs/%v.key", *id)
	cert, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		log.Fatalf("Could not load server TLS certificate: %v", err)
	}

	return cert
}

func initClients(hosts []string, myAddr string) {

	isReady = make(chan struct{}, len(hosts))

	// initialize channels with correct amount of buffer space
	canReceiveKeys = make(chan struct{}, len(hosts))
	canReceiveAlphaBeta = make(chan struct{}, len(hosts))
	canReceiveGammasDeltas = make(chan struct{}, len(hosts))
	canReceivePhis = make(chan struct{}, len(hosts))

	// generate clients sequentially, not so bad
	for _, host := range hosts {
		if host == myAddr {
			continue
		}

		// Get certificate
		cert := getClientCertificate()

		// Configure options to Dial
		var opts []grpc.DialOption
		opts = append(opts, grpc.WithTransportCredentials(cert))
		opts = append(opts, grpc.WithBackoffMaxDelay(1*time.Second))
		opts = append(opts, grpc.WithBlock())

		// Set up a connection to the server.
		conn, err := grpc.Dial(host, opts...)
		if err != nil {
			log.Fatalf("Did not connect (to host %v): %v", host, err)
		}
		// defer conn.Close() TODO: This needs to happen at somepoint, but not here
		c := pb.NewZKPAuctionClient(conn)

		clients = append(clients, c)
	}

	// log.Println("Finishing initializing clients")
}

func main() {
	flag.Parse()

	myState = &state{}

	hosts := getHosts()
	myAddr := hosts[*id]

	go runServer(myAddr)

	initClients(hosts, myAddr)

	myState.round1()

	// TODO millionaire specific shit
	myState.round2()
	myState.millionaire_MixOutput1()
	myState.millionaire_MixOutput2()
	myState.millionaire_RandomizeOutput()
	myState.millionaire_Decryption()

	// TODO do this better
	for {
	}
}

// TODO use as part of library code
func (s *state) publishAll(result *pb.Result) {
	// Signal to all receivers that we can receive now
	for i := 0; i < len(clients); i++ {
		isReady <- struct{}{}
	}

	// Publish data to all clients
	for _, client := range clients {
		// log.Println("Sending data to client...")
		client := client
		go func() {
			// Needs to be a goroutine because otherwise we block waiting for a response
			_, err := client.Publish(context.Background(), result)
			if err != nil {
				log.Fatalf("Error on sending data: %v", err)
			}
		}()
	}
}

// TODO use inside of gRPC publish call
func (s *state) checkAll(check CheckFn) {
	for i := 0; i < len(clients); i++ {
		result := <-receivedChan
		go func() {
			err := check(&result)
			if err == nil {
				checkedChan <- result
			}
		}()
	}
}

type CheckFn func(*pb.Result) error
type ReceiveFn func(state interface{}, result []*pb.OuterStruct)

func (s *state) checkRound1(result *pb.OuterStruct) (err error) {
	var key pb.Key

	var k, t, r big.Int

	err = proto.Unmarshal(result.GetData(), &key)
	if err != nil {
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

func (s *state) checkRound2(result *pb.OuterStruct) (err error) {
	var in pb.AlphaBeta

	err = proto.Unmarshal(result.GetData(), &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal pb.AlphaBeta.\n")
	}

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

func (s *state) checkRound3(result *pb.OuterStruct) (err error) {
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
}

func (s *state) checkRound4(result *pb.OuterStruct) (err error) {
	var in pb.DecryptionInfo

	err = proto.Unmarshal(result.GetData(), &in)
	if err != nil {
		log.Fatalf("Failed to unmarshal pb.DecryptionInfo.\n")
	}

	if len(in.Phis) != len(in.Proofs) || uint(len(in.Proofs)) != zkp.K_Mill {
		log.Printf("len of phis=%v, len of proofs=%v, k=%v\n", len(in.Phis), uint(len(in.Proofs)), zkp.K_Mill)
		log.Fatalf("Incorrect number of shit5")
	}

	for j := 0; j < len(in.Phis); j++ {
		var phi big.Int
		phi.SetBytes(in.Phis[j])

		var bases, results, ts []big.Int
		// proof equality of logarithms of the received phi and their public key
		bases = append(bases, *zkp.G)
		results = append(results, phi)

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
			log.Fatalf("Received incorrect zero-knowledge proof for phis")
		}
	}
}

func receiveRound1(state interface{}, results []*pb.OuterStruct) {
	var s *state
	s, err := state.(state)
	if err != nil {
		log.Fatalf("Failed to typecast state.\n")
	}

	var key pb.Key

	s.keys = append(s.keys, s.myPublicKey)

	for i := 0; i < len(results); i++ {
		err = proto.Unmarshal(results[i].GetData(), &key)
		if err != nil {
			log.Fatalf("Failed to unmarshal pb.Key.\n")
		}
		var k big.Int
		k.SetBytes(key.key)
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

func receiveRound2(state interface{}, results []*pb.OuterStruct) {
	var s *state
	s, err := state.(state)
	if err != nil {
		log.Fatalf("Failed to typecast state.\n")
	}

	var alphabeta pb.AlphaBeta
	s.theirAlphasBetas = &AlphaBetaStruct{}

	// Wait for alphas and betas of other client
	for i := 0; i < len(clients); i++ {
		err = proto.Unmarshal(results[i].GetData(), &alphabeta)
		if err != nil {
			log.Fatalf("Failed to unmarshal pb.AlphaBeta.\n")
		}
		r := results[i]
		for j := 0; j < len(alphabeta.GetAlphas()); j++ {
			s.theirAlphasBetas.alphas = append(s.theirAlphasBetas.alphas, *new(big.Int).SetBytes(alphaBeta.GetAlphas()[j]))
			s.theirAlphasBetas.betas = append(s.theirAlphasBetas.betas, *new(big.Int).SetBytes(alphaBeta.GetBetas()[j]))
		}
	}
}

// TODO delete comment
/*
 * 1. Generates a private/public key pair
 * 2. Generates zero-knowledge-proof of private key
 * 3. Publishes the public key with zero-knowledge proof of private key
 * 4. Puts our own public key in state.keys
 * 5. Receives n public keys from keyChan, puts them in state.keys
 * 6. Calculates the final public key, and stores into state.
 */
func (s *state) round1() {
	// Generate private key
	s.myPrivateKey.Rand(zkp.RandGen, zkp.Q)
	// Calculate public key
	s.myPublicKey.Exp(zkp.G, &s.myPrivateKey, zkp.P)

	// Generate zkp of private key
	t, r := zkp.DiscreteLogKnowledge(s.myPrivateKey, *zkp.G, *zkp.P, *zkp.Q)
	// Create proto structure of zkp
	zkpPrivKey := &pb.DiscreteLogKnowledge{T: t.Bytes(), R: r.Bytes()}

	result := pb.Result{
		Round: 1,
		Key: &pb.Key{
			Key:   s.myPublicKey.Bytes(),
			Proof: zkpPrivKey,
		},
	}

	s.publishAll(&result)
	s.checkAll(s.checkRound1)

	s.keys = append(s.keys, s.myPublicKey)

	// Wait for public keys of all other clients
	for i := 0; i < len(clients); i++ {
		r := <-checkedChan
		var k big.Int
		k.SetBytes(r.Key.Key)
		s.keys = append(s.keys, k)
	}

	// Calculating final public key
	// TODO SHOULD THIS BE MOD P? Probably doesn't matter, but just for computational practicality
	s.publicKey.Set(zkp.One)
	for _, key := range s.keys {
		s.publicKey.Mul(&s.publicKey, &key)
	}
	s.publicKey.Mod(&s.publicKey, zkp.P)

	log.Printf("Calculated public key: %v\n", s.publicKey.String())
}

func (s *state) round2() {
	// Publish alphas and betas to all of the clients

	var alphas, betas [][]byte
	var alphasInts, betasInts []big.Int

	var proofs []*pb.EqualsOneOfTwo

	var j uint
	for j = 0; j < zkp.K_Mill; j++ {
		var alphaJ, betaJ, rJ big.Int
		rJ.Rand(zkp.RandGen, zkp.Q)

		log.Printf("r_%v,%v = %v\n", *id, j, rJ.String())

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
		log.Printf("alpha_%v: %v\n", j, alphaJ)
		log.Printf("beta_%v: %v\n", j, betaJ)

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

	result := pb.Result{
		Round: 2,
		AlphaBeta: &pb.AlphaBeta{
			Alphas: alphas,
			Betas:  betas,
			Proofs: proofs,
		},
	}

	s.publishAll(&result)
	s.checkAll(s.checkRound2)

	s.myAlphasBetas = &AlphaBetaStruct{
		alphas: alphasInts,
		betas:  betasInts,
	}

	s.theirAlphasBetas = &AlphaBetaStruct{}

	// Wait for alphas and betas of other client
	// TODO len should just be 1
	// TODO error handling
	for i := 0; i < len(clients); i++ {
		r := <-checkedChan
		alphaBeta := r.AlphaBeta
		for j := 0; j < len(alphaBeta.Alphas); j++ {
			s.theirAlphasBetas.alphas = append(s.theirAlphasBetas.alphas, *new(big.Int).SetBytes(alphaBeta.Alphas[j]))
			s.theirAlphasBetas.betas = append(s.theirAlphasBetas.betas, *new(big.Int).SetBytes(alphaBeta.Betas[j]))
		}
	}

	log.Printf("theirAlphasBetas: %v %v\n", s.theirAlphasBetas.alphas, s.theirAlphasBetas.betas)
}

func (s *state) millionaire_MixOutput1() {
	// mostly a no-op just calculate (gamma, delta)
	var gds *millionaire.GammaDeltaStruct
	if *id == 0 {
		gds = millionaire.MillionaireCalculateGammaDelta(s.myAlphasBetas.alphas, s.theirAlphasBetas.alphas,
			s.myAlphasBetas.betas, s.theirAlphasBetas.betas, *zkp.Y_Mill, *zkp.P)
	} else {
		gds = millionaire.MillionaireCalculateGammaDelta(s.theirAlphasBetas.alphas, s.myAlphasBetas.alphas,
			s.theirAlphasBetas.betas, s.myAlphasBetas.betas, *zkp.Y_Mill, *zkp.P)
	}
	// TODO for now just set both
	s.myGammasDeltas = gds
	s.theirGammasDeltas = gds

	log.Printf("Gammas/deltas: %v\n", gds)
}

func (s *state) millionaire_MixOutput2() {
	// no-op for now
}

// Takes gamme and delta to a random exponent, proves the equality of the exponent (logarithm)
func (s *state) millionaire_RandomizeOutput() {
	// log.Println("Beginning random exponentiation")

	var proofs []*pb.DiscreteLogEquality

	var exponentiatedGammas, exponentiatedDeltas [][]byte

	s.myExponentiatedGammasDeltas = new(millionaire.GammaDeltaStruct)

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

		log.Printf("m_%v = %v, gamma_%v = %v, delta_%v = %v\n", j, m.String(), j, newGamma.String(), j, newDelta.String())

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

	// Signal to all receivers that we can receive now
	for i := 0; i < len(clients); i++ {
		canReceiveGammasDeltas <- struct{}{}
	}

	// Publish public key to all clients
	for _, client := range clients {
		client := client
		// log.Println("Sending exponentiated exponentiatedGammas/exponentiatedDeltas...")
		go func() {
			// Needs to be a goroutine because otherwise we block waiting for a response
			_, err := client.MillionaireRandomizeOutput(context.Background(),
				&pb.RandomizedOutput{
					Gammas: exponentiatedGammas,
					Deltas: exponentiatedDeltas,
					Proofs: proofs,
				})
			if err != nil {
				log.Fatalf("Error on sending exponentiated gammas/deltas: %v", err)
			}
		}()
	}

	// log.Println("Beginning random exponentiation8")

	// Wait for gammas/deltas of all other clients (should be just 1 for millionaire)
	// TODO error handling
	for i := 0; i < len(clients); i++ {
		s.theirExponentiatedGammasDelta = <-exponentiatedGammasDeltasChan
	}

	// log.Println("Beginning random exponentiation9")

	log.Printf("Received exponentiated gammas/deltas %v", s.theirExponentiatedGammasDelta)
	// TODO calcualte the final shit
}

// Calculates phis in order to decrypt them
func (s *state) millionaire_Decryption() {
	// log.Println("Beginning decryption")

	var proofs []*pb.DiscreteLogEquality

	var phis [][]byte

	s.myPhis = new(millionaire.PhiStruct)
	s.phisBeforeExponentiation = new(millionaire.PhiStruct)

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

		log.Printf("Before exponentiation, phi_%v = %v\n", i, phi2.String())

		phi.Exp(&phi, &s.myPrivateKey, zkp.P)
		s.myPhis.Phis = append(s.myPhis.Phis, phi)

		log.Printf("phi_%v = %v\n", i, phi.String())

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

	// Signal to all receivers that we can receive now
	for i := 0; i < len(clients); i++ {
		canReceivePhis <- struct{}{}
	}

	// Publish public key to all clients
	for _, client := range clients {
		client := client
		// log.Println("Sending exponentiated phis... %v", s.myPhis.Phis)
		go func() {
			// Needs to be a goroutine because otherwise we block waiting for a response
			_, err := client.MillionaireDecryptionInfo(context.Background(),
				&pb.DecryptionInfo{
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

	// Calculate the final shit (division + which one is bigger)
	for j := 0; j < int(zkp.K_Mill); j++ {
		v := millionaire.MillionaireCalculateV(s.myExponentiatedGammasDeltas.Gammas[j], s.theirExponentiatedGammasDelta.Gammas[j], s.myPhis.Phis[j], s.theirPhis.Phis[j], *zkp.P)
		log.Printf("v_%v = %v\n", j, v)
		if v.Cmp(zkp.One) == 0 {
			log.Fatalf("ID 0 is the winner\n")
		}
	}
	log.Fatalf("ID 1 is the winner\n")
}
