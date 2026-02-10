import re
import csv
from collections import Counter, defaultdict
from datetime import datetime
import os

# Config
LOG_FILE = "data/sample.log"
OUTPUT_DIR = "outputs"
BRUTE_FORCE_THRESHOLD = 10  # Failed 401s
SUSPICIOUS_ENDPOINTS = ["/admin", "/login", "/wp-login.php"]

# Regex for Apache Common Log Format: IP - - [time] "METHOD path PROTO" status bytes ...
LOG_PATTERN = re.compile(
    r'^(\S+) \S+ \S+ \\[(.*?)\\] "(?:\S+) (\S+) \S+" (\d+) \S+'
)

def load_logs(file_path):
    """Load and parse log lines into dicts."""
    logs = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                match = LOG_PATTERN.match(line.strip())
                if match:
                    ip, timestamp, endpoint, status = match.groups()
                    logs.append({
                        'ip': ip,
                        'timestamp': timestamp,
                        'endpoint': endpoint,
                        'status': int(status),
                        'line': line_num
                    })
                else:
                    print(f"Warning: Skipped invalid line {line_num}: {line.strip()[:50]}...")
        print(f"Loaded {len(logs)} valid log entries.")
        return logs
    except FileNotFoundError:
        print(f"Error: {file_path} not found. Create it with sample data.")
        return []

def analyze_requests_per_ip(logs):
    """Count total requests per IP."""
    ip_counts = Counter(entry['ip'] for entry in logs)
    return ip_counts.most_common()

def detect_brute_force(logs):
    """IPs with > threshold failed logins (401)."""
    failed_logins = defaultdict(int)
    for entry in logs:
        if entry['status'] == 401 and '/login' in entry['endpoint']:
            failed_logins[entry['ip']] += 1
    suspicious = {ip: count for ip, count in failed_logins.items() if count >= BRUTE_FORCE_THRESHOLD}
    return dict(suspicious)

def detect_suspicious_endpoints(logs):
    """Hits to sensitive paths."""
    suspicious_hits = defaultdict(list)
    for entry in logs:
        for sensitive in SUSPICIOUS_ENDPOINTS:
            if sensitive in entry['endpoint']:
                suspicious_hits[entry['ip']].append({
                    'endpoint': entry['endpoint'],
                    'status': entry['status'],
                    'time': entry['timestamp']
                })
    return dict(suspicious_hits)

def save_results(ip_counts, brute_force, suspicious):
    """Save to CSV."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = os.path.join(OUTPUT_DIR, "results.csv")
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Analysis', 'Details'])
        writer.writerow(['Top IPs (requests)', ''])
        for ip, count in ip_counts[:10]:
            writer.writerow([ip, count])
        writer.writerow(['Brute-force IPs (401 fails)', ''])
        for ip, count in brute_force.items():
            writer.writerow([ip, count])
        writer.writerow(['Suspicious endpoint hits', ''])
        for ip, hits in list(suspicious.items())[:5]:  # Limit
            for hit in hits:
                writer.writerow([f"{ip}: {hit['endpoint']}", f"Status {hit['status']}"])
    print(f"Results saved to {filename}")

def main():
    logs = load_logs(LOG_FILE)
    if not logs:
        return

    print("\n=== TOP REQUESTS PER IP ===")
    ip_counts = analyze_requests_per_ip(logs)
    for ip, count in ip_counts[:10]:
        print(f"{ip}: {count} requests")

    print("\n=== BRUTE-FORCE DETECTION (401 login fails >10) ===")
    brute_force = detect_brute_force(logs)
    if brute_force:
        for ip, count in brute_force.items():
            print(f"ALERT: {ip} - {count} failed logins!")
    else:
        print("No brute-force detected.")

    print("\n=== SUSPICIOUS ENDPOINTS ===")
    suspicious = detect_suspicious_endpoints(logs)
    if suspicious:
        for ip, hits in suspicious.items():
            print(f"{ip}: {len(hits)} hits to sensitive paths ({[h['endpoint'] for h in hits[:3]]})")
    else:
        print("No suspicious endpoints hit.")

    save_results(ip_counts, brute_force, suspicious)
    print("\nAnalysis complete! Check outputs/ and README.")

if name == "__main__":
    main()
