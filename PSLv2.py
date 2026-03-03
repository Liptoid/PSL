import nmap
import requests
import argparse
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

# ==========================
# Banner
# ==========================
def banner():
    console.print("""
██╗     ██╗██████╗ ████████╗ ██████╗ ██╗██████╗ 
██║     ██║██╔══██╗╚══██╔══╝██╔═══██╗██║██╔══██╗
██║     ██║██████╔╝   ██║   ██║   ██║██║██║  ██║
██║     ██║██╔═══╝    ██║   ██║   ██║██║██║  ██║
███████╗██║██║        ██║   ╚██████╔╝██║██████╔╝
╚══════╝╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝╚═════╝ 
Advanced Nmap + CVE Scanner V2
""", style="bold cyan")


# ==========================
# CVE Lookup
# ==========================
def search_cves(service, version):
    query = f"{service} {version}"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 3
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        data = response.json()

        results = []

        if "vulnerabilities" in data:
            for item in data["vulnerabilities"]:
                cve_id = item["cve"]["id"]

                metrics = item["cve"].get("metrics", {})
                cvss_score = "N/A"

                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

                results.append({
                    "id": cve_id,
                    "cvss": cvss_score
                })

        return results

    except:
        return []


# ==========================
# Risk Level
# ==========================
def risk_level(score):
    try:
        score = float(score)
        if score >= 9:
            return "CRITICAL"
        elif score >= 7:
            return "HIGH"
        elif score >= 4:
            return "MEDIUM"
        else:
            return "LOW"
    except:
        return "UNKNOWN"


# ==========================
# Scan Function
# ==========================
def run_scan(target, mode):
    nm = nmap.PortScanner()

    arguments = "-F -sV" if mode == "fast" else "-p- -sV"

    console.print(f"[+] Scanning {target} in {mode.upper()} mode...\n", style="bold yellow")
    nm.scan(target, arguments=arguments)

    results = []

    table = Table(title="Scan Results")
    table.add_column("Port")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("Top CVE")
    table.add_column("CVSS")
    table.add_column("Risk")

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()

            for port in ports:
                port_data = nm[host][proto][port]

                if port_data["state"] == "open":
                    service = port_data.get("name", "unknown")
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    full_version = f"{product} {version}".strip()

                    cves = search_cves(service, full_version)

                    if cves:
                        top_cve = cves[0]["id"]
                        cvss = cves[0]["cvss"]
                        risk = risk_level(cvss)
                    else:
                        top_cve = "None"
                        cvss = "N/A"
                        risk = "N/A"

                    table.add_row(
                        str(port),
                        service,
                        full_version,
                        top_cve,
                        str(cvss),
                        risk
                    )

                    results.append({
                        "port": port,
                        "service": service,
                        "version": full_version,
                        "cves": cves
                    })

    console.print(table)
    return results


# ==========================
# Save Report
# ==========================
def save_report(target, data):
    filename = f"liptoid_scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    console.print(f"\n[+] Report saved: {filename}", style="bold green")


# ==========================
# Main
# ==========================
if __name__ == "__main__":
    banner()

    parser = argparse.ArgumentParser(description="Liptoid Advanced Scanner V2")
    parser.add_argument("target", help="Target IP or Domain")
    parser.add_argument("--mode", choices=["fast", "full"], default="fast")

    args = parser.parse_args()

    console.print("[!] Use only on systems you own or have permission.\n", style="bold red")

    scan_results = run_scan(args.target, args.mode)
    save_report(args.target, scan_results)