print("🔥 CYBERSECURITY ANALYST TOOL - BULLETPROOF VERSION")
print("Parsing your exact log format...")

import os
from collections import Counter, defaultdict

log_file = "data/sample.log"

# Read logs
with open(log_file, 'r') as f:
    lines = f.readlines()

logs = []
for line_num, line in enumerate(lines, 1):
    line = line.strip()
    if not line: 
        continue
    
    # SPLIT AND FIND POSITIONS SAFELY
    parts = line.split()
    if len(parts) < 10:
        continue
        
    ip = parts[0]
    
    # FIND STATUS CODE (always near end, skip if not number)
    status = None
    for i in range(len(parts)-2, 4, -1):  # Look backward from end
        try:
            status = int(parts[i])
            break
        except ValueError:
            continue
    
    if status is None:
        continue
        
    # FIND ENDPOINT (word with / inside quotes)
    endpoint = "/"
    for part in parts:
        if '"' in part and '/' in part:
            endpoint = part.strip('"')
            break
    
    logs.append({
        'ip': ip, 
        'status': status, 
        'endpoint': endpoint,
        'line': line_num
    })

print(f"✅ PARSED {len(logs)} threat events!")

if not logs:
    print("❌ No valid logs. Check data/sample.log format.")
    exit()

# === REAL-TIME SOC ANALYSIS ===
print("\n" + "="*60)
print("SECURITY OPERATIONS CENTER - THREAT REPORT")
print("="*60)

print("\n📊 TOP ATTACKERS BY REQUEST VOLUME:")
ip_requests = Counter(log['ip'] for log in logs).most_common(5)
for ip, count in ip_requests:
    print(f"   {ip:15} {count:>3} requests")

print("\n🚨 BRUTE FORCE ATTACK DETECTED:")
brute_force = Counter()
for log in logs:
    if log['status'] == 401 and 'login' in log['endpoint'].lower():
        brute_force[log['ip']] += 1

for ip, count in brute_force.items():
    if count >= 3:
        print(f"   🛑 CRITICAL: {ip} - {count} FAILED LOGINS!")
    else:
        print(f"   ⚠️   {ip} - {count} failed logins")

print("\n🔍 SUSPICIOUS ENDPOINT ACTIVITY:")
suspicious_paths = ['login', 'admin', 'wp-login']
for log in logs:
    if any(path in log['endpoint'].lower() for path in suspicious_paths):
        marker = "🛑" if log['status'] != 200 else "ℹ️"
        print(f"   {marker} {log['ip']:15} → {log['endpoint'][:30]:30} ({log['status']})")

print("\n" + "="*60)
print("MISSION SUMMARY")
print("="*60)
print(f"📈 Total events analyzed: {len(logs)}")
print(f"🔥 Most active IP: {ip_requests[0][0]}")
print(f"🚨 Confirmed brute force attacks: {sum(1 for v in brute_force.values() if v >= 3)}")
print(f"✅ SOC ANALYST TOOL OPERATIONAL")
print("💼 Portfolio-ready: git add . && git commit -m 'Working SOC tool'")