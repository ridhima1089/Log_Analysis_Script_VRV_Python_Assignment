# Log Analysis Script

## Description of the Submission

This Python script performs log analysis on a given log file (`sample.log`) to extract valuable insights, including:

### Counting Requests per IP Address

The script processes the log entries and counts the number of requests made by each unique IP address. The results are displayed in descending order of request counts.

### Identifying the Most Frequently Accessed Endpoint

The script extracts the endpoints (URLs or resource paths) accessed in the log file. It then identifies and displays the endpoint(s) that were accessed the most frequently.

### Detecting Suspicious Activity

The script looks for failed login attempts (HTTP status code 401 or "Invalid credentials" message). It flags IP addresses with failed login attempts exceeding a given threshold (default: 10 attempts). Suspicious IPs are displayed along with the count of failed login attempts.

## Output

The results are displayed in the terminal in an organized and clear format, including:

- Request counts per IP address.
- The most frequently accessed endpoint(s).
- Suspicious IPs with failed login attempts.

The results are also saved to a CSV file (`log_analysis_results.csv`) in a structured format:

- **Requests per IP**: Columns for IP Address and Request Count.
- **Most Accessed Endpoint(s)**: Columns for Endpoint and Access Count.
- **Suspicious Activity**: Columns for IP Address and Failed Login Attempts.

## Key Features

### 1. Log Parsing

The script begins by reading the log file line by line. This is done using the `parse_log_file()` function, which handles file reading and error checking for missing or inaccessible files. If the log file is not found, an error message is displayed, and the function returns an empty list.

### 2. IP Request Counting

The script uses a regular expression to extract the IP addresses from each log entry. This is done by matching the IP address at the start of each line (with `IP_REGEX`). 

The `analyze_logs()` function uses the `Counter` class from Python’s `collections` module to count the number of requests made by each IP address. The counts are stored in a `Counter` object, which is later used to display the IP request counts in descending order.

### 3. Endpoint Analysis

The script extracts the endpoints (URLs or resource paths) from each log entry using another regular expression (`ENDPOINT_REGEX`). It matches the GET or POST method followed by the endpoint. 

The `analyze_logs()` function stores the frequency of each accessed endpoint in a `Counter` object, which is used to identify the most frequently accessed endpoint. The script finds the endpoint with the highest count and stores the result.

### 4. Suspicious Activity Detection

The script detects potential brute force login attempts by searching for failed login attempts in the logs. It looks for HTTP status code 401 or the phrase “Invalid credentials” in each log entry.

The `analyze_logs()` function tracks the number of failed login attempts per IP address using a `defaultdict(int)`. If an IP address exceeds the configured threshold (default is 10 failed attempts), it is flagged as suspicious. The flagged IPs and their failed login counts are stored in a dictionary, which is then used to display suspicious activity.

### 5. Results Display

The results are displayed in the terminal in a structured format:

- IP request counts are displayed in descending order with IP addresses and their corresponding request counts.
- Most frequently accessed endpoint(s) is shown along with the number of accesses.
- Suspicious activity is displayed, listing IP addresses that exceed the failed login threshold and the number of failed login attempts for each.

The results are printed in a clear tabular format, making it easy to interpret.

### 6. Saving Results to CSV

The script also saves the analysis results to a CSV file for further review. The `save_results_to_csv()` function writes the following data to `log_analysis_results.csv`:

- **Requests per IP**: A table with IP addresses and their corresponding request counts.
- **Most Accessed Endpoint(s)**: A table showing the most accessed endpoints and their access counts.
- **Suspicious Activity**: A table listing suspicious IPs and their failed login attempt counts.

The CSV output is formatted with headers and is structured to match the requirements.

### 7. Error Handling

The script includes error handling to ensure smooth execution:

- If the log file is not found, an error message is displayed, and an empty result is saved.
- If there is an issue with saving the CSV file (e.g., if the file is open or locked), an appropriate error message is displayed.

### 8. Customizable Threshold

The script allows you to configure the threshold for suspicious activity detection. The default value is set to 10 failed login attempts, but this can be adjusted by passing a different threshold value to the `analyze_logs()` function.

### 9. Modularity

The script is designed in a modular fashion, with each function focusing on a specific task. This structure enhances code readability and maintainability.

- `parse_log_file()`: Reads the log file.
- `analyze_logs()`: Processes log entries to count requests, identify most accessed endpoints, and detect suspicious activity.
- `save_results_to_csv()`: Saves the results to a CSV file.
- `display_results()`: Displays the results in the terminal.
- `main()`: The main function that orchestrates the entire process.

By keeping the script modular and efficient, it ensures the ability to handle large log files, making it both scalable and maintainable.
