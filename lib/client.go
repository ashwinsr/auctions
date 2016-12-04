package lib

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/ashwinsr/auctions/pb"
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
	id           int
	numRound     int32 = 0
	data         []*pb.OuterStruct
	dataLock     sync.Mutex
	clientsReady sync.Once
)

// channels for each round
/*
 * These are here so that protobuf data, if received before we have moved
 * onto the next round, just wait in the channel until we are ready.
 */
var (
	clients []pb.ZKPAuctionClient
	// Publish
	// isReady      chan struct{}
	receivedIdChan chan int32 = make(chan int32)
	isReady        chan bool  = make(chan bool, 1)
)

// TODO millionaire specific
// TODO delete

var (
	hostsFileName = flag.String("hosts", "../hosts.json", "JSON file with lists of hosts to communicate with")
)

// server is used to implement pb.ZKPAuctionServer
type server struct{}

func (s *server) Publish(ctx context.Context, in *pb.OuterStruct) (*google_protobuf.Empty, error) {
	// fmt.Println("Publish Publish Publish")

	go func() {
		// fmt.Println("Before wedding")
		clientsReady.Do(func() {
			// fmt.Println("In the wedding")
			<-isReady
		})
		// fmt.Println("After wedding")

		fmt.Println(in.GetClientid())

		// TODO THIS IS FUCKING STUPID BUT OK FOR NOW
		dataLock.Lock()
		data[in.GetClientid()] = in
		dataLock.Unlock()

		receivedIdChan <- in.GetClientid()
	}()

	return &google_protobuf.Empty{}, nil
}

// Listens for connections; meant to be run in a goroutine
func RunServer(localHost string) {
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

func GetHosts() []string {
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
	certFile := fmt.Sprintf("../certs/%v.pem", id)
	cert, err := credentials.NewClientTLSFromFile(certFile, "")
	if err != nil {
		log.Fatalf("Could not load client TLS certificate: %v", err)
	}

	return cert
}

func getServerCertificate() credentials.TransportCredentials {
	certFile := fmt.Sprintf("../certs/%v.pem", id)
	keyFile := fmt.Sprintf("../certs/%v.key", id)
	cert, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		log.Fatalf("Could not load server TLS certificate: %v", err)
	}

	return cert
}

func InitClients(hosts []string, myAddr string) {
	fmt.Println("InitClients InitClients InitClients")
	// generate clients sequentially, not so bad
	for _, host := range hosts {
		fmt.Println("LOOP START")
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
		fmt.Println("LOOP END")
	}

	data = make([]*pb.OuterStruct, len(clients)+1)
	fmt.Println(len(data))
	// log.Println("Finishing initializing clients")
	isReady <- true
}

type Round struct {
	Compute ComputeFn
	Check   CheckFn
	Receive ReceiveFn
}

type ComputeFn func(interface{}) proto.Message
type CheckFn func(interface{}, *pb.OuterStruct) error
type ReceiveFn func(interface{}, []*pb.OuterStruct)

func marshalData(result proto.Message) (r []byte) {
	r, err := proto.Marshal(result)
	if err != nil {
		log.Fatalf("Could not marshal data %v", result)
	}
	return
}

// TODO use as part of library code
func publishAll(out *pb.OuterStruct) {
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
func checkAll(state interface{}, check CheckFn) {
	var wg sync.WaitGroup
	wg.Add(len(clients))

	for i := 0; i < len(clients); i++ {
		idx := <-receivedIdChan
		result := data[idx]
		go func() {
			defer wg.Done()
			err := check(state, result)
			if err != nil {
				log.Fatalf("Error!!!")
			}
		}()
	}

	wg.Wait()
}

func Register(rounds []Round, state interface{}) {
	for _, round := range rounds {
		result := round.Compute(state)
		numRound++
		var mData []byte
		if result == nil {
			mData = []byte{}
		} else {
			mData = marshalData(result)
		}
		out := &pb.OuterStruct{
			Clientid: int32(id),
			Stepid:   numRound,
			Data:     mData,
		}
		publishAll(out)
		checkAll(state, round.Check)
		round.Receive(state, data)
	}
}

func Init(id_ int) {
	id = id_
}
