print("🚀 Starting Cybersecurity Log Analysis...")
import os
print(f"Working directory: {os.getcwd()}")

# Check file exists
log_file = "data/sample.log"
if not os.path.exists(log_file):
    print("❌ data/sample.log missing! Run the echo commands above.")
else:
    print("✅ Log file found!")

# Simple log parser - NO regex needed
logs = []
try:
    with open(log_file, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 10:
                ip = parts[0]
                status = int(parts[-2])  # Status code is second-to-last
                endpoint = parts[6]      # Endpoint is 7th field
                logs.append({'ip': ip, 'endpoint': endpoint, 'status': status})
    print(f"✅ Parsed {len(logs)} log entries!")
except:
    print("❌ Error reading log file")

if logs:
    print("\n=== TOP IPs ===")
    from collections import Counter
    ip_counts = Counter(log['ip'] for log in logs).most_common(5)
    for ip, count in ip_counts:
        print(f"  {ip}: {count} requests")
    
    print("\n=== BRUTE FORCE ALERTS ===")
    brute_ips = [log['ip'] for log in logs if log['status'] == 401 and 'login' in log['endpoint']]
    if brute_ips:
        from collections import Counter
        brute_count = Counter(brute_ips)
        for ip, count in brute_count.items():
            if count >= 2:  # Simple threshold
                print(f"🚨 {ip}: {count} failed logins!")
    else:
        print("  No brute force detected")
    
    print("\n✅ ANALYSIS COMPLETE!")
else:
    print("No logs to analyze. Check data/sample.log")