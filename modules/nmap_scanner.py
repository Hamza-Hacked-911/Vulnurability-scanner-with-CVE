import nmap

def scan_target(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV')
    scan_data = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]
                scan_data.append({
                    'ip': host,
                    'port': port,
                    'name': service['name'],
                    'product': service['product'],
                    'version': service['version']
                })
    print(f"Scan data collected: {scan_data}")
    return scan_data
