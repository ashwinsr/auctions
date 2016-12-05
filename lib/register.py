import json
import certificates

OUTPUT_FILENAME = 'hosts.auc'

def build_client_list():
    print "*****AUCTION*****"
    print "To register for auction, you need to supply us with some basic details."

    clients = []
    client_id = 0
    while True:
        client_ip = raw_input("IP: ")
        client_port = raw_input("Port: ")
        client_certificate = certificates.generate(client_ip, client_id)
        clients.append(client_ip + ":" + client_port)

        client_id += 1
        registerMore = raw_input("Register more? ").strip().lower()[0]
        if registerMore != 'y': break

    return clients

def dump_client_list(clients):
    with open(OUTPUT_FILENAME, 'w') as f:
        f.write(json.dumps({'hosts': clients}))

if __name__ == "__main__":
    certificates.initialize()
    clients = build_client_list()
    certificates.end()
    
    dump_client_list(clients)
