import csv
from collections import defaultdict, Counter
import re

# Constants
DEFAULT_FAILED_THRESHOLD = 10
LOG_FILE = 'sample.log'
CSV_OUTPUT_FILE = 'log_analysis_results.csv'

# Regular expressions for log parsing
IP_REGEX = r'^(\S+)'  # Matches the IP address at the beginning of the log line
ENDPOINT_REGEX = r'"(?:GET|POST) (\S+)'  # Matches the endpoint in the log line

# Function to parse log file
def parse_log_file(file_path):
    """
    Reads the log file line by line.

    Args:
        file_path (str): Path to the log file.

    Returns:
        list[str]: List of log lines or an empty list if the file doesn't exist.
    """
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
        return []

# Function to analyze log entries
def analyze_logs(log_lines, failed_threshold=DEFAULT_FAILED_THRESHOLD):
    """
    Analyzes log lines to extract request counts, endpoints, and suspicious IPs.

    Args:
        log_lines (list[str]): List of log file lines.
        failed_threshold (int): Threshold for flagging suspicious activity.

    Returns:
        tuple: A Counter of IP requests, a list of most accessed endpoints, 
               and a dict of suspicious IPs with failed attempts.
    """
    ip_request_count = Counter()
    endpoint_count = Counter()
    failed_login_attempts = defaultdict(int)

    for line in log_lines:
        # Extract IP address
        ip_match = re.match(IP_REGEX, line)
        if ip_match:
            ip_address = ip_match.group(1)
            ip_request_count[ip_address] += 1

        # Extract endpoint
        endpoint_match = re.search(ENDPOINT_REGEX, line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_count[endpoint] += 1

        # Check for failed login attempts
        if '401' in line or 'Invalid credentials' in line:
            if ip_match:
                failed_login_attempts[ip_address] += 1

    max_access_count = max(endpoint_count.values(), default=0)
    most_accessed_endpoints = [
        (endpoint, count)
        for endpoint, count in endpoint_count.items()
        if count == max_access_count
    ]

    suspicious_ips = {
        ip: count
        for ip, count in failed_login_attempts.items()
        if count > failed_threshold
    }

    return ip_request_count, most_accessed_endpoints, suspicious_ips


def save_results_to_csv(ip_data, endpoint_data, suspicious_data, file_path):
    """
    Saves analyzed data to a CSV file. Reports an error if the file is open or locked.

    Args:
        ip_data (Counter): Count of requests per IP.
        endpoint_data (list[tuple]): Most accessed endpoints with their counts.
        suspicious_data (dict): Suspicious IPs with failed login attempts.
        file_path (str): Path to the CSV output file.
    """
    try:
        with open(file_path, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)

            # Write requests per IP
            writer.writerow(['Requests per IP'])
            writer.writerow(['IP Address', 'Request Count'])
            for ip, count in ip_data.items():
                writer.writerow([ip, count])

            # Write most accessed endpoint(s)
            writer.writerow([])
            writer.writerow(['Most Accessed Endpoint(s)'])
            if endpoint_data:
                for endpoint, count in endpoint_data:
                    writer.writerow([endpoint, count])
            else:
                writer.writerow(['None', 0])

            # Write suspicious activity
            writer.writerow([])
            writer.writerow(['Suspicious Activity'])
            writer.writerow(['IP Address', 'Failed Login Attempts'])
            if suspicious_data:
                for ip, count in suspicious_data.items():
                    writer.writerow([ip, count])
            else:
                writer.writerow(['None', 0])

        # Print success message
        print(f"\nResults successfully saved to '{file_path}'")

    except PermissionError:
        print(f"\nError: The file '{file_path}' is currently open or locked. Please close it and try again.")



# Function to display results
def display_results(ip_request_count, most_accessed_endpoints, suspicious_ips):
    """
    Displays analyzed results in the terminal.

    Args:
        ip_request_count (Counter): Count of requests per IP.
        most_accessed_endpoints (list[tuple]): Most accessed endpoints with their counts.
        suspicious_ips (dict): Suspicious IPs with failed login attempts.
    """
    print("\nIP Address           | Request Count")
    print("-" * 40)
    for ip, count in ip_request_count.most_common():
        print(f"{ip:<20} | {count}")

    print("\nMost Frequently Accessed Endpoints:")
    if most_accessed_endpoints:
        for endpoint, count in most_accessed_endpoints:
            print(f"{endpoint} (Accessed {count} times)")
    else:
        print("No endpoints accessed.")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           | Failed Login Attempts")
        print("-" * 40)
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} | {count}")
    else:
        print("No suspicious activity detected.")

# Main function
def main(log_file=LOG_FILE, csv_output_file=CSV_OUTPUT_FILE, failed_threshold=DEFAULT_FAILED_THRESHOLD):
    """
    Main function to parse logs, analyze data, display results, and save to CSV.

    Args:
        log_file (str): Path to the log file.
        csv_output_file (str): Path to the CSV output file.
        failed_threshold (int): Threshold for flagging suspicious activity.
    """
    # Parse the log file
    log_lines = parse_log_file(log_file)

    if not log_lines:
        print("No log entries found. The file is empty or not accessible.")
        save_results_to_csv({}, [], {}, csv_output_file)
        print(f"\nResults saved to {csv_output_file}")
        return

    # Analyze logs
    ip_request_count, most_accessed_endpoints, suspicious_ips = analyze_logs(
        log_lines, failed_threshold
    )

    # Display results
    display_results(ip_request_count, most_accessed_endpoints, suspicious_ips)

    # Save results to CSV
    save_results_to_csv(ip_request_count, most_accessed_endpoints, suspicious_ips, csv_output_file)


if __name__ == "__main__":
    main()
