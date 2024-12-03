import re
import csv
from collections import defaultdict

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Initialize counters and data structures
ip_requests = defaultdict(int)
endpoint_access = defaultdict(int)
failed_logins = defaultdict(int)

# Parse the log file
with open("sample.log", "r") as log_file:
    for line in log_file:
        # Extract IP, endpoint, and status code
        ip_match = re.search(r'^([\d\.]+)', line)
        endpoint_match = re.search(r'\"[A-Z]+\s(\/[\w\/]+)', line)
        status_match = re.search(r'\" \d{3}', line)
        
        if ip_match:
            ip = ip_match.group(1)
            ip_requests[ip] += 1
            
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_access[endpoint] += 1
            
        if status_match and "401" in line:
            failed_logins[ip] += 1

# Sort results
sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1])
suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

# Print results
print("IP Address           Request Count")
for ip, count in sorted_ip_requests:
    print(f"{ip:<20}{count}")
    
print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

print("\nSuspicious Activity Detected:")
print("IP Address           Failed Login Attempts")
for ip, count in suspicious_ips.items():
    print(f"{ip:<20}{count}")

# Write to CSV
with open("log_analysis_results.csv", "w", newline='') as csv_file:
    writer = csv.writer(csv_file)
    
    # Requests per IP
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(sorted_ip_requests)
    
    # Most Accessed Endpoint
    writer.writerow([])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow(most_accessed_endpoint)
    
    # Suspicious Activity
    writer.writerow([])
    writer.writerow(["IP Address", "Failed Login Count"])
    writer.writerows(suspicious_ips.items())
