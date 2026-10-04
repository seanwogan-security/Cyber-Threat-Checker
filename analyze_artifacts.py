
"""
analyze_artifacts.py (Simple Version)

• Reads the JSON file created by the PowerShell script
• Extracts unique remote IP addresses
• Checks those IPs using the VirusTotal API
• Saves the results into another JSON file
• Shows a simple summary in the terminal

This matches the lecture/lab requirements:
- File I/O (opening, reading, writing JSON files)
- Data structures (lists, sets, dictionaries)
- Loops and conditionals
- Error handling with try/except
- External library: requests
- Security API usage (VirusTotal)
"""

import json
import time
from pathlib import Path
import requests



# Load configuration file

def load_config(path):
    """Load config.json and return it as a Python dictionary."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print("[!] Error loading config file:", e)
        exit(1)



# Load artifacts from PowerShell

def load_artifacts(path):
    """Load the JSON file created by the PowerShell script."""
    try:
        # utf-8-sig ignores the BOM that PowerShell adds
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception as e:
        print("[!] Error loading artifacts file:", e)
        exit(1)


# Extract unique remote IP addresses

def extract_ips(artifacts):
    """Return a set of unique remote IP addresses."""
    ip_set = set()

    for conn in artifacts.get("Connections", []):
        ip = conn.get("RemoteAddress")

        # Skip empty/localhost addresses
        if not ip:
            continue
        if ip in ["0.0.0.0", "127.0.0.1", "::1"]:
            continue

        ip_set.add(ip)

    return ip_set



# Query VirusTotal

def query_virustotal(ip, api_key, timeout):
    """Send a request to VirusTotal for an IP address."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    try:
        response = requests.get(url, headers={"x-apikey": api_key}, timeout=timeout)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": True, "status": response.status_code}

    except Exception as e:
        return {"error": True, "message": str(e)}



# Extract malicious count from VT response

def get_malicious_count(vt_data):
    """Return the 'malicious' engine count, or 0 if not available."""
    try:
        stats = vt_data["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0)
    except:
        return 0



# Main program

def main():

    print("[*] Loading config...")
    config = load_config("config.json")

    api_key = config["virustotal_api_key"]
    input_path = Path(config["input_artifacts_path"])
    output_path = Path(config["output_report_path"])
    max_ips = config.get("max_ips_to_check", 20)
    timeout = config.get("request_timeout_seconds", 15)

    # --- Load artifacts ---
    print("[*] Loading artifacts...")
    artifacts = load_artifacts(input_path)

    # --- Extract IPs ---
    ips = extract_ips(artifacts)
    print(f"[*] Found {len(ips)} unique remote IPs.")

    # Limit how many IPs we check (to avoid API limits)
    ips_to_check = list(ips)[:max_ips]

    results = {}

    # --- Query VirusTotal for each IP ---
    for i, ip in enumerate(ips_to_check, start=1):
        print(f"[*] Checking {ip} ({i}/{len(ips_to_check)})")

        vt_data = query_virustotal(ip, api_key, timeout)
        malicious = get_malicious_count(vt_data)

        results[ip] = {
            "malicious_count": malicious,
            "virustotal_data": vt_data
        }

        time.sleep(1)  # be gentle to the API

    # --- Build report dictionary ---
    report = {
        "hostname": artifacts.get("Hostname"),
        "collected_at": artifacts.get("CollectedAt"),
        "total_ips_found": len(ips),
        "ips_checked": len(ips_to_check),
        "ip_results": results
    }

    # --- Save report ---
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Report saved to {output_path}")

    # --- Summary output ---
    print("\n=== Summary ===")
    print("Malicious IPs:")
    for ip, info in results.items():
        if info["malicious_count"] > 0:
            print(f"  - {ip} (malicious: {info['malicious_count']})")


if __name__ == "__main__":
    main()
