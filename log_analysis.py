import csv
import logging
import re
from collections import defaultdict

# Step 1: Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Step 2: Read the log file with error handling
try:
    with open('sample.log', 'r') as file:
        logs = file.readlines()
    logging.info("Log file read successfully.")
except FileNotFoundError:
    logging.error("Log file not found.")
    exit()
except PermissionError:
    logging.error("Permission denied to read the log file.")
    exit()

# Check if the log file is empty
if not logs:
    logging.error("The log file is empty.")
    exit()

# Step 3: Count requests by each IP
ip_counts = defaultdict(int)

for line in logs:
    ip = line.split()[0]
    ip_counts[ip] += 1

if ip_counts:
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    logging.info("IP Address           Request Count")
    for ip, count in sorted_ips:
        logging.info(f"{ip:<20}{count}")
else:
    logging.error("No IP addresses found in the log file.")

# Step 4: Count requests per endpoint using regular expressions
endpoint_counts = defaultdict(int)
malformed_endpoint_count = 0

endpoint_pattern = r'\"(GET|POST|PUT|DELETE) (\S+) HTTP/1.1\"'
for line in logs:
    match = re.search(endpoint_pattern, line)
    if match:
        endpoint = match.group(2)
        endpoint_counts[endpoint] += 1
    else:
        malformed_endpoint_count += 1
        logging.warning(f"Skipping malformed endpoint: {line}")

if endpoint_counts:
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    logging.info(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")
else:
    logging.info("\nNo valid endpoints found in the log file.")

# Step 5: Count failed login attempts
failed_attempts = defaultdict(int)
threshold = 10

for line in logs:
    if '401' in line or 'Invalid credentials' in line:
        ip = line.split()[0]
        failed_attempts[ip] += 1

suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}

if suspicious_ips:
    logging.info("\nSuspicious Activity Detected:")
    logging.info("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        logging.info(f"{ip:<20}{count}")
else:
    logging.info("\nNo suspicious activity detected.")

# Step 6: Prepare all data to write to CSV
rows = []

# Adding IP Counts to rows
rows.append(['IP Address', 'Request Count'])
rows.extend(sorted_ips)

# Adding Most Accessed Endpoint
rows.append([])  # Blank line
rows.append(['Most Accessed Endpoint', 'Access Count'])
if endpoint_counts:
    rows.append([most_accessed[0], most_accessed[1]])

# Adding Suspicious IPs
rows.append([])  # Blank line
rows.append(['IP Address', 'Failed Login Count'])
rows.extend(suspicious_ips.items())

# Writing all data to CSV
with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(rows)

logging.info("Results saved to log_analysis_results.csv.")

# Log the count of malformed endpoints
logging.info(f"Total malformed endpoint lines skipped: {malformed_endpoint_count}")
