Registering for an auction
--------------------------
First, start up the server using `python register_server.py`. By default it
will run on port 80.

Creating a new auction: curl <Server IP>/create
Registering for a new auction: wget --content-disposition <Server IP>/register
Downloading the auction file: wget --content-disposition <Server IP>/download_auc

A few notes about registering for an auction:
1. By convention, the seller should first create the auction, and be the first
   to register for the auction.
2. Registering for the auction will automatically download signed certificates.
   Place the certificate and the key in the certs/ folder.
3. Download the auction file after every bidder has registered. Overwrite the
   existing hosts.auc file in the home directory.

Running an auction
------------------
After registration is completed, to run an auction, go into the first_price/
folder and execute:
	  go run *.go -bid=<BID VALUE>

Note, that we have currently limited bids to be 0 <= BID VALUE < 100.