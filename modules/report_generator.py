def generate_report(vulnerabilities):
    report = "HAZOO Vulnerability Scanner - Vulnerability Report\n\n"
    if not vulnerabilities:
        report += "No vulnerabilities found.\n"
    for vuln in vulnerabilities:
        report += f"IP: {vuln['ip']}\n"
        report += f"Port: {vuln['port']}\n"
        report += f"Service: {vuln['name']}\n"
        report += f"Product: {vuln['product']}\n"
        report += f"Version: {vuln['version']}\n"
        report += f"CVE: {vuln['cve']}\n"
        report += f"Description: {vuln['description']}\n"
        report += "-" * 40 + "\n"
    with open("vulnerability_report.txt", "w") as file:
        file.write(report)
    print(f"HAZOO Vulnerability Scanner - Report content: {report}")

def save_scan_data(scan_data, filename):
    scan_report = "HAZOO Vulnerability Scanner - Scan Data Report\n\n"
    for item in scan_data:
        scan_report += f"IP: {item['ip']}\n"
        scan_report += f"Port: {item['port']}\n"
        scan_report += f"Service: {item['name']}\n"
        scan_report += f"Product: {item['product']}\n"
        scan_report += f"Version: {item['version']}\n"
        scan_report += "-" * 40 + "\n"
    with open(filename, "w") as file:
        file.write(scan_report)
    print(f"HAZOO Vulnerability Scanner - Scan data saved to {filename}")
