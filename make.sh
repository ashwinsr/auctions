export PATH=$PATH:$GOPATH/bin
protoc -I distribute/pb distribute/pb/comm.proto --go_out=plugins=grpc:distribute/pb

cd distribute
go build
