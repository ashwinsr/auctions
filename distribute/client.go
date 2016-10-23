package main

import (
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/ashwinsr/auctions/distribute/pb"
	"github.com/ashwinsr/auctions/zkp"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"golang.org/x/net/context"

	"net/http"
	_ "net/http/pprof"
)

// TODO debugging
func init() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
}

// Need to convert to using command line options for a lot of these

// Note we have no fault tolerance in these protocols.

// keeps state
type state struct {
	myPrivateKey big.Int
	myPublicKey  big.Int
	keys         []big.Int
	publicKey    big.Int
}

// channels for each round
/*
 * These are here so that protobuf data, if received before we have moved
 * onto the next round, just wait in the channel until we are ready.
 */
var (
	clients []pb.ZKPAuctionClient
	keyChan chan big.Int = make(chan big.Int) // TODO bother with buffer?
)

var (
	hostsFileName = flag.String("hosts", "hosts.json", "JSON file with lists of hosts to communicate with")
	id            = flag.Int("id", -1, "ID")
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
	// TODO debugging
	// if *id == 0 {
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
		defer conn.Close()
		c := pb.NewZKPAuctionClient(conn)

		clients = append(clients, c)
	}

	log.Println("Finishing initializing clients")
	// }
}

func main() {
	flag.Parse()

	myState := &state{}

	hosts := getHosts()
	myAddr := hosts[*id]

	go runServer(myAddr)

	initClients(hosts, myAddr)

	myState.keyDistribution()

	// TODO debugging
	// if *id == 1 {
	// 	for {
	// 	}
	// }
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
	s.myPublicKey.Exp(zkp.Q, &s.myPrivateKey, zkp.P)

	log.Printf("My public key: %v\n", s.myPublicKey)

	// Generate zkp of private key
	t, r := zkp.DiscreteLogKnowledge(s.myPrivateKey, *zkp.G, *zkp.P, *zkp.Q)
	// Create proto structure of zkp
	zkpPrivKey := &pb.DiscreteLogKnowledge{T: t.Bytes(), R: r.Bytes()}

	// TODO debugging
	// if *id == 0 {
	// Publish public key to all clients
	for _, client := range clients {
		log.Println("Sending key to client...")
		go func() {
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

	// TODO debugging
	log.Printf("Keys: %v", s.keys)

	for _, key := range s.keys {
		s.publicKey.Add(&s.publicKey, &key)
	}
	// }
}
