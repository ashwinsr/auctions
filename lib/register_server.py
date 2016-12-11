######################INSTRUCTIONS#####################
#
# To create a new auction: curl localhost:5000/create
# To register for the auction: wget --content-disposition localhost:5000/register
# To download the auction file: wget --content-disposition localhost:5000/download_auc
#
########################################################

from flask import Flask, request, Response
import certificates
app = Flask(__name__)

##### BEGIN AUCTION CLASS #####

class Auction:
    def __init__(self, seller_ip):
        self.next_port = 9000
        self.seller = seller_ip + ":" + self.get_next_port()
        self.buyers = []

    def get_next_port(self):
        self.next_port += 1
        return str(self.next_port)

    def register_buyer(self, buyer_ip):
        # Get this persons ID
        buyer_id = len(self.buyers)

        # Generate a certificate for this person
        certs = certificates.generate(buyer_ip, buyer_id)
        
        # Add them to the list of buyers
        self.buyers.append(buyer_ip + ":" + self.get_next_port())
        return certs, buyer_id

##### END AUCTION CLASS #####

##### BEGIN SERVER CODE #####

auction = None

def get_request_IP(request):
    return request.access_route[0]

@app.route('/create')
def create_auction():
    global auction
    request_ip = get_request_IP(request)

    # Create a new auction and set the seller
    auction = Auction(request_ip)
    return "You have successfully created a new auction!\n"

@app.route('/register')
def register():
    global auction
    if auction is None:
        return "No open auction exists\n"
    request_ip = get_request_IP(request)

    # Add this requester to the list of hosts and get certs
    certs, id = auction.register_buyer(request_ip)

    return Response(certs, mimetype="text/plain", headers={"Content-Disposition": "attachment;filename=" + str(id) + ".zip"})

@app.route('/download_auc')
def download_auction_file():
    global auction
    if auction is None:
        return "No open auction exists\n"
    request_ip = get_request_IP(request)

    # Create auction file for this person
    # List of hosts, my host, my ID, seller
    return "You are downloading the auction file!\n"

##### END SERVER CODE #####
