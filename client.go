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

var (
	round int32
	data  []*pb.OuterStruct
)

// channels for each round
/*
 * These are here so that protobuf data, if received before we have moved
 * onto the next round, just wait in the channel until we are ready.
 */
var (
	clients []pb.ZKPAuctionClient
	// Publish
	isReady      chan struct{}
	receivedChan chan pb.Result = make(chan pb.Result)
)

// TODO millionaire specific
// TODO delete

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
		// <-isReady

		data[in.GetClientid()] = *in

		// receivedChan <- *in
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

var ()

type Round struct {
	compute ComputeFn
	check   CheckFn
	receive ReceiveFn
}

type CheckFn func(*pb.OuterStruct) error
type ReceiveFn func(state interface{}, result []*pb.OuterStruct)
type ComputeFn func(state interface{}) interface{}

func Register(rounds []Round) {
	for i := 0; i < len(rounds); i++ {

	}
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
func publishAll(out *pb.OuterStruct) {
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
			_, err := client.Publish(context.Background(), out)
			if err != nil {
				log.Fatalf("Error on sending data: %v", err)
			}
		}()
	}
}

// TODO use inside of gRPC publish call
func checkAll(check CheckFn) {
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

func getState(state interface{}) (s *state) {
	s, err := state.(state)
	if err != nil {
		log.Fatalf("Failed to typecast state.\n")
	}
}

// func marshalData(result []*pb.OuterStruct) []bytes {
//
// }
