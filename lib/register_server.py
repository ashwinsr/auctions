######################INSTRUCTIONS#####################
#
# To create a new auction: curl localhost:5000/create
# To register for the auction: wget --content-disposition localhost:5000/register
# To download the auction file: wget --content-disposition localhost:5000/download_auc
#
########################################################

from flask import Flask, request, Response
import certificates
import json
app = Flask(__name__)

##### BEGIN AUCTION CLASS #####

class Auction:
    def __init__(self):
        self.next_port = 9000
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

    def get_address_and_id(self, ip):
        for id, host in enumerate(self.buyers):
            if host.split(':')[0] == ip:
                return host, id

        return None, None

    def get_auc_file(self, ip):
        myAddress, myID = self.get_address_and_id(ip)
        if myAddress is None: return None

        auction = {}
        auction["myID"]      = myID
        auction["seller"]    = self.buyers[0]
        auction["hosts"]     = self.buyers

        return auction

##### END AUCTION CLASS #####

##### BEGIN SERVER CODE #####

auction = None

def get_request_IP(request):
    return request.access_route[0]

@app.route('/create')
def create_auction():
    global auction
    request_ip = get_request_IP(request)

    # Create a new auction
    auction = Auction()
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

    # Create and return an auc file for this person
    auc_file = auction.get_auc_file(request_ip)
    if auc_file is None:
        return "You are not registered for this auction!\n"

    auc_json = json.dumps(auc_file)
    return Response(auc_json, mimetype="text/plain", headers={"Content-Disposition": "attachment;filename=hosts.auc"})

##### END SERVER CODE #####
