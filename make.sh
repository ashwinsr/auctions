export PATH=$PATH:$GOPATH/bin
protoc -I pb -I $GOPATH pb/comm.proto --go_out=plugins=grpc:pb

go build
