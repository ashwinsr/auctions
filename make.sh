export PATH=$PATH:$GOPATH/bin
cd $GOPATH/src
protoc github.com/ashwinsr/auctions/millionaire/millionaire.proto --go_out=.
protoc github.com/ashwinsr/auctions/lib/pb/comm.proto --go_out=plugins=grpc:.
protoc github.com/ashwinsr/auctions/common_pb/common.proto --go_out=.

go build
