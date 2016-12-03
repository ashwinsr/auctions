TODO

- Move things to command line arguments
- Write python "Makefile" (runs protobuf generator and go test)
- Write better discovery of hosts


1.
- SSL (look into how gRPC deals with SSL. Need to encrypt with our private key and their public key)
- Incorporate random shuffle
- Factor ZKP code

2.
- Generalize
- Joining an auction (auction file formats, etc.)
- Read 2006 paper

3.
- 2006 paper (in generalized framework)

4.
FIX OUR TWO SECURITY BUGS:
-We have two rpc functions connecting over SSL. It needs to be peer authentication, one bidirectional connection per client (connect to someone lower than you, establish a bidirectional stream of OuterStructs. Both sides need to check each others' certificates.
-CANNOT pass client_id over network, a client can fake that

5.
- Further (general purpose auctions, multi-unit auctions...)
