import nmap

def scan_local_network(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')

    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()}) is {nm[host].state()}")

if __name__ == "__main__":
    # adresse ip rechercher
    local_network = "192.168.87.197/25"
    
    print(f"Scanning local network: {local_network}")
    scan_local_network(local_network)


