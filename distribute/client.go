package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/ashwinsr/auctions/distribute/pb"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// Need to convert to using command line options for a lot of these

// Note we have no fault tolerance in these protocols.

// TODO CONVERT THESE STATES TO A PIPELINE DAMNIT
// enumerates the states we can be in: basically, which round of
// communication we are in.
const (
	START = iota + 1
	HAVE_KEYS
)

var currState = START
var keys []big.Int

var (
	hostsFileName = flag.String("hosts", "hosts.json", "JSON file with lists of hosts to communicate with")
	id            = flag.Int("id", -1, "ID")
)

// server is used to implement pb.ZKPAuctionServer
type server struct{}

// SendKey implements pb.ZKPAuctionServer
func (s *server) SendKey(ctx context.Context, in *pb.Key) (*google_protobuf.Empty, error) {
	if currState != START {
		return nil, fmt.Errorf("Received new key after receiving all keys...")
	}
	// parse big.Int

	// change state if necessary
	// TODO ACTUALLY WANT A PIPELINE, SEND KEY INTO CHANNEL
	return &google_protobuf.Empty{}, nil
}

func main() {
	hostsFile, err := os.Open(*hostsFileName)
	if err != nil {
		fmt.Printf("Error opening hosts file: %v", err)
		os.Exit(1)
	}

	var hosts struct {
		Hosts []string `json:"hosts"`
	}

	if err = json.NewDecoder(hostsFile).Decode(&hosts); err != nil {
		fmt.Printf("Error opening hosts file: %v", err)
		os.Exit(1)
	}

	// TODO create server

	// TODO generate key

	// TODO create slice of clients

	// TODO publish key to all clients (look for efficient broadcast)

}
