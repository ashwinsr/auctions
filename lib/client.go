package lib

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"crypto/tls"
	"crypto/x509"

	"google.golang.org/grpc"

	pb "github.com/ashwinsr/auctions/common_pb"
	lib_pb "github.com/ashwinsr/auctions/lib/pb"
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
	clients []lib_pb.ZKPAuctionClient
	// Publish
	receivedIdChan chan int32    = make(chan int32)
	isReady        chan struct{} = make(chan struct{}, 1)
	seller 		   lib_pb.ZKPAuctionClient
	readyToReceiveNextRound *sync.Cond
	numRoundLock            sync.Mutex
)

// TODO millionaire specific
// TODO delete

var (
	hostsFileName = flag.String("hosts", "../hosts.auc", "JSON file with lists of hosts to communicate with")
)

// server is used to implement lib_pb.ZKPAuctionServer
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

		// log.Println("Received Client id: ", in.Clientid, "\n")
		numRoundLock.Lock()

		for {
			// log.Printf("For looping client id %v\n", in.Clientid)
			if in.Stepid == numRound {
				break
			}
			readyToReceiveNextRound.Wait()
			// log.Printf("Got through (client id %v)\n", in.Clientid)
		}

		// TODO THIS IS FUCKING STUPID BUT OK FOR NOW
		dataLock.Lock()
		data[in.Clientid] = in
		dataLock.Unlock()
		log.Printf("RECEIVED DATA FOR ROUND ***************************** %v, Client id: %v", in.Stepid, in.Clientid)

		numRoundLock.Unlock()

		receivedIdChan <- in.Clientid
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
	lib_pb.RegisterZKPAuctionServer(s, &server{})
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

func getRootCertificate() []byte {
	cert, err := ioutil.ReadFile("../certs/ca.cert")
	if err != nil {
		log.Fatalf("Could not load root CA certificate.")
	}

	return cert
}

func getClientCertificate() credentials.TransportCredentials {
	// Create CA cert pool
	caCert := getRootCertificate()
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	certFileName := fmt.Sprintf("../certs/%v.cert", id)
	keyFileName := fmt.Sprintf("../certs/%v.key", id)
	myCert, err := tls.LoadX509KeyPair(certFileName, keyFileName)
	if err != nil {
		log.Fatalf("Could not load client TLS certificate: %v", err)
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{myCert},
		RootCAs:      caPool,
	})
}

func getServerCertificate() credentials.TransportCredentials {
	// Create CA cert pool
	caCert := getRootCertificate()
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	certFile := fmt.Sprintf("../certs/%v.cert", id)
	keyFile := fmt.Sprintf("../certs/%v.key", id)
	myCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Could not load server TLS certificate: %v", err)
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{myCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
}

func InitClients(hosts []string, myAddr string) {
	fmt.Println("InitClients InitClients InitClients")
	// generate clients sequentially, not so bad
	for i, host := range hosts {

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
		c := lib_pb.NewZKPAuctionClient(conn)

		clients = append(clients, c)

		if i == 0 {
			seller = c
		}
	}

	data = make([]*pb.OuterStruct, len(clients)+1)

	readyToReceiveNextRound = sync.NewCond(&numRoundLock)

	isReady <- struct{}{}
}

type Round struct {
	Compute ComputeFn
	Check   CheckFn
	Receive ReceiveFn
}

type ComputeFn func(interface{}) (proto.Message, bool)
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
func PublishAll(out *pb.OuterStruct) {
	// Publish data to all clients
	for _, client := range clients {
		// log.Println("Sending data to client...")
		client := client
		go func() {
			// Needs to be a goroutine because otherwise we block waiting for a response
			log.Printf("ID:%v Publishing to clientid:%v for Round:%v", id, out.Clientid, out.Stepid)
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

	clientsReceiving := make(map[int32]bool)

	for i := 0; i <= len(clients); i++ {
		if i == id {
			continue	
		}
		clientsReceiving[int32(i)] = true
	}

	log.Printf("Preparing to Receive from %v", len(clientsReceiving))
	for len(clientsReceiving) != 0 {
		
		idx := <-receivedIdChan

		if int32(id) == idx {
			continue
		}

		dataLock.Lock()
		result := data[idx]
		dataLock.Unlock()

		log.Printf("Checking client id %v", idx)

		go func() {
			defer wg.Done()
			err := check(state, result)
			if err != nil {
				log.Fatalf("Error!!!")
			}
		}()

		_, ok := clientsReceiving[idx];
    	if ok {
        	delete(clientsReceiving, idx);
    	}
    	log.Printf("Remaining to receive from %v clients", len(clientsReceiving))
	}

	wg.Wait()
}

func Register(rounds []Round, state interface{}) {
	for _, round := range rounds {
		result, sendToSeller := round.Compute(state)
		
		var mData []byte
		if result == nil {
			mData = []byte{}
		} else {
			mData = marshalData(result)
		}
		out := &pb.OuterStruct{
			Clientid: int32(id),
			Stepid:   numRound + 1,
			Data:     mData,
		}

		// Now that we've computed and marshalled
		// tell everyone we can receive stuff from the next round
		numRoundLock.Lock()
		numRound++
		readyToReceiveNextRound.Broadcast()
		numRoundLock.Unlock()

		if sendToSeller {
			if id != 0 {
				log.Printf("Sending to Seller")
				_, err := seller.Publish(context.Background(), out)
				if err != nil {
					log.Fatalf("Error on sending data to seller: %v", err)
				}
			}
		} else {
			log.Printf("Publishing %v", round, id)
			PublishAll(out)	
		}

		// log.Printf("Checking...")
		checkAll(state, round.Check)
		// log.Printf("Receiving...")
		round.Receive(state, data)
	}
}

func Init(id_ int) {
	id = id_
}
