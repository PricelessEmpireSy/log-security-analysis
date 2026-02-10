import re
import csv
from collections import Counter, defaultdict
import os

LOG_FILE = "data/sample.log"
OUTPUT_DIR = "outputs"
BRUTE_FORCE_THRESHOLD = 10
SUSPICIOUS_ENDPOINTS = ["/admin", "/login", "/wp-login.php"]

LOG_PATTERN = re.compile(r'(\S+) \S+ \S+ \\[(?:.*?)\\] "(?:\S+) (\S+) \S+" (\d+)', re.IGNORECASE)

def load_logs(file_path):
    logs = []
    total_lines = 0
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                line = line.strip()
                if not line: continue
                match = LOG_PATTERN.search(line)
                if match:
                    ip, endpoint, status_str = match.groups()
                    try:
                        status = int(status_str)
                        logs.append({'ip': ip, 'endpoint': endpoint, 'status': status, 'line': line_num})
                    except ValueError:
                        pass
        print(f"Loaded {len(logs)} valid entries from {total_lines} total lines.")
        return logs
    except FileNotFoundError:
        print(f"ERROR: {file_path} missing. Create data/ folder and sample.log.")
        return []
    except Exception as e:
        print(f"ERROR loading logs: {e}")
        return []

# [Rest of functions unchanged: analyze_requests_per_ip, detect_brute_force, detect_suspicious_endpoints, save_results]

def analyze_requests_per_ip(logs):
    return Counter(entry['ip'] for entry in logs).most_common()

def detect_brute_force(logs):
    failed_logins = defaultdict(int)
    for entry in logs:
        if entry['status'] == 401 and 'login' in entry['endpoint'].lower():
            failed_logins[entry['ip']] += 1
    return {ip: count for ip, count in failed_logins.items() if count >= BRUTE_FORCE_THRESHOLD}

def detect_suspicious_endpoints(logs):
    suspicious_hits = defaultdict(list)
    for entry in logs:
        for sensitive in SUSPICIOUS_ENDPOINTS:
            if sensitive in entry['endpoint']:
                suspicious_hits[entry['ip']].append({'endpoint': entry['endpoint'], 'status': entry['status']})
    return dict(suspicious_hits)

def save_results(ip_counts, brute_force, suspicious):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = os.path.join(OUTPUT_DIR, "results.csv")
    try:
        with open(filename, 'w', newline='', encoding='utf-8-sig', errors='replace') as f:
            writer = csv.writer(f)
            writer.writerow(['Top IPs'])
            for ip, count in ip_counts[:10]:
                writer.writerow([ip, count])
            writer.writerow(['', ''])
            writer.writerow(['Brute-Force'])
            for ip, count in brute_force.items():
                writer.writerow([ip, count])
            writer.writerow(['', ''])
            writer.writerow(['Suspicious Hits'])
            for ip, hits in suspicious.items():
                writer.writerow([ip, len(hits)])
        print(f"Saved: {filename}")
    except Exception as e:
        print(f"CSV save error: {e}")

def main():
    logs = load_logs(LOG_FILE)
    if not logs: return

    print("\n=== TOP REQUESTS ===")
    ip_counts = analyze_requests_per_ip(logs)
    for ip, count in ip_counts[:5]:
        print(f"{ip}: {count}")

    print("\n=== BRUTE-FORCE ===")
    brute_force = detect_brute_force(logs)
    for ip, count in brute_force.items():
        print(f"🚨 {ip}: {count} fails!")

    print("\n=== SUSPICIOUS ===")
    suspicious = detect_suspicious_endpoints(logs)
    for ip, hits in suspicious.items():
        print(f"{ip}: {len(hits)} hits")

    save_results(ip_counts, brute_force, suspicious)
    print("\n✅ Done!")

if name == "__main__":
    main()
    