import requests

def fetch_cve_data(product, version):
    # Simplify version by removing extra details
    simplified_version = version.split()[0]
    url = f'https://cve.circl.lu/api/search/{product}/{simplified_version}'
    print(f"HAZOO Vulnerability Scanner - Fetching CVE data from URL: {url}")
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"HAZOO Vulnerability Scanner - Failed to fetch CVE data for {product} {version}")
        return None

def identify_vulnerabilities(scan_data):
    vulnerabilities = []
    for service in scan_data:
        if service['product'] and service['version']:
            print(f"HAZOO Vulnerability Scanner - Checking CVEs for product: {service['product']}, version: {service['version']}")
            cve_data = fetch_cve_data(service['product'], service['version'])
            if cve_data:
                for item in cve_data:
                    vulnerabilities.append({
                        'ip': service['ip'],
                        'port': service['port'],
                        'name': service['name'],
                        'product': service['product'],
                        'version': service['version'],
                        'cve': item['id'],
                        'description': item['summary']
                    })
            else:
                print(f"HAZOO Vulnerability Scanner - No CVE data found for {service['product']} {service['version']}")
    return vulnerabilities
