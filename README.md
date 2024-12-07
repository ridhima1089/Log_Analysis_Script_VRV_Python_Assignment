# Log_Analysis_Script_VRV_Python_Assignment

## Description of the Submission
This Python script performs log analysis on a given log file (sample.log) to extract valuable insights, including:

Counting Requests per IP Address:

The script processes the log entries and counts the number of requests made by each unique IP address.
The results are displayed in descending order of request counts.
Identifying the Most Frequently Accessed Endpoint:

The script extracts the endpoints (URLs or resource paths) accessed in the log file.
It then identifies and displays the endpoint(s) that were accessed the most frequently.
Detecting Suspicious Activity:

The script looks for failed login attempts (HTTP status code 401 or "Invalid credentials" message).
It flags IP addresses with failed login attempts exceeding a given threshold (default: 10 attempts).
Suspicious IPs are displayed along with the count of failed login attempts.
Output:

The results are displayed in the terminal in an organized and clear format, including:
Request counts per IP address.
The most frequently accessed endpoint(s).
Suspicious IPs with failed login attempts.
The results are also saved to a CSV file (log_analysis_results.csv) in a structured format:
Requests per IP: Columns for IP Address and Request Count.
Most Accessed Endpoint(s): Columns for Endpoint and Access Count.
Suspicious Activity: Columns for IP Address and Failed Login Attempts.
