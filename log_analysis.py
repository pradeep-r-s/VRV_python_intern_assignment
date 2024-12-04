import re
import csv
from collections import defaultdict, Counter

# Constants
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 5  # Configurable threshold for suspicious activity

# Functions
def parse_log_file(file_path):
    """Parses the log file and returns structured data."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = Counter()

    with open(file_path, 'r') as file:
        for line in file:
            # Regex patterns to match log details
            ip_pattern = r'^([\d\.]+)'  # Match IP address
            endpoint_pattern = r'\"[A-Z]+ (.+?) HTTP'  # Match endpoint
            status_pattern = r'HTTP/\d\.\d\" (\d{3})'  # Match status code

            # Extract details
            ip = re.search(ip_pattern, line)
            endpoint = re.search(endpoint_pattern, line)
            status = re.search(status_pattern, line)

            if ip:
                ip = ip.group(1)
                ip_requests[ip] += 1
            if endpoint:
                endpoint = endpoint.group(1)
                endpoint_requests[endpoint] += 1
            if status and status.group(1) == '401':  # Failed login detection
                if ip:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def identify_suspicious_ips(failed_logins, threshold):
    """Identifies suspicious IPs based on failed login attempts."""
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def save_to_csv(ip_requests, most_accessed, suspicious_ips, output_file):
    """Saves the analysis results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Empty row

        # Write most accessed endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow(most_accessed)

        writer.writerow([])  # Empty row

        # Write suspicious activity
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    # Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)

    # Identify the most accessed endpoint
    most_accessed = endpoint_requests.most_common(1)[0]

    # Detect suspicious activity
    suspicious_ips = identify_suspicious_ips(failed_logins, FAILED_LOGIN_THRESHOLD)

    # Display results
    print("\nRequests per IP:")
    for ip, count in ip_requests.items():
        print(f"{ip}\t{count}")

    print("\nMost Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip}\t{count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed, suspicious_ips, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
