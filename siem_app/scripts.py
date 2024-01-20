import requests
import os
import re
import requests
import pandas as pd
import subprocess
import csv
from bs4 import BeautifulSoup
from celery import shared_task
from urllib.parse import urljoin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report
from .models import ScanResults
from numba import jit

#_____________________

#Web Server Scanner - CYRIL OAKS
#_____________________

def scan_website(website_url):

    additional_flags = ['-no404', '-nossl', '-timeout', '2', '-nointeractive', '-C', 'none', '-Tuning', '1:0']
    process = subprocess.Popen(['nikto', '-h', website_url] + additional_flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode('utf-8')

#_____________________

#Web Crawler - CYRIL OAKS 
#_____________________

def crawl_website(url):
    # Send a GET request to the URL
    response = requests.get(url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Parse the HTML content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract and print all URLs on the page
        links = soup.find_all('a', href=True)

        # Accumulate URLs in a list
        absolute_urls = [urljoin(url, link['href']) for link in links]

        # Return the list of URLs
        return absolute_urls

    else:
        print(f"Failed to fetch the page. Status code: {response.status_code}")
        return []

#_____________________

#Log File Analyser - CYRIL OAKS
#_____________________

def get_cve_info(cve_id):
    base_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
    url = f"{base_url}/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def extract_relevant_data(log_entry):
    relevant_data = set()  # Using a set to avoid duplicates
    
    # Split the log entry into words
    words = log_entry.split()
    
    # Define patterns for different types of data
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]*:){2,7}[0-9a-fA-F]+\b'
    url_pattern = r'https?://\S+'
    error_code_pattern = r'\b\d{3}\b'

    for word in words:
        # Check for IP addresses
        if re.match(ip_pattern, word):
            relevant_data.add(word)
        
        # Check for URLs
        if re.match(url_pattern, word):
            relevant_data.add(word)
        
        # Check for error codes
        if re.match(error_code_pattern, word):
            relevant_data.add(word)
    
    return list(relevant_data)


# Function to crawl the system for log files
def crawl_system_for_logs(root_directory):
    log_files = []
    for root, dirs, files in os.walk(root_directory):
        for file in files:
            if file.endswith(".log"):
                log_file_path = os.path.join(root, file)
                log_files.append(log_file_path)
                print(f"Found log file: {log_file_path}")
    return log_files


# Function to analyze log files
def analyse_logs(log_files):
    log_data = []
    suspicious_logs_paths = []  # List to store the paths of files containing suspicious logs

    for log_file in log_files:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                log_data.append(line)
                if 'error' in line.lower():
                    suspicious_logs_paths.append(log_file)

    # You would need to define more sophisticated rules or use a machine learning model to classify log entries here.
    # For simplicity, we are just checking if a line contains the word 'error'.
    suspicious_logs = [line for line in log_data if 'error' in line.lower()]
    normal_logs = [line for line in log_data if 'error' not in line.lower()]

    return normal_logs, suspicious_logs, suspicious_logs_paths


# Machine Learning model (Naive Bayes classifier) for log analysis
def train_and_evaluate_classifier(normal_logs, suspicious_logs):
    data = normal_logs + suspicious_logs
    labels = [0] * len(normal_logs) + [1] * len(suspicious_logs)  # 0 for normal, 1 for suspicious
    
    # Text Vectorization
    vectorizer = TfidfVectorizer()
    data_vectorized = vectorizer.fit_transform(data)
    
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(data_vectorized, labels, test_size=0.2, random_state=42)
    
    # Train a Naive Bayes classifier
    clf = MultinomialNB()
    clf.fit(X_train, y_train)
    
    # Predict labels for the test data
    y_pred = clf.predict(X_test)
    
    # Evaluate the model
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Normal', 'Suspicious'])
    
    return accuracy, report, y_pred


def run_log_analysis():
    root_directory = "/"
    log_files = crawl_system_for_logs(root_directory)
    print(f"Found {len(log_files)} log files.")
    
    normal_logs, suspicious_logs, suspicious_logs_paths = analyse_logs(log_files)
    print(f"Analyzed {len(normal_logs)} normal logs and {len(suspicious_logs)} suspicious logs.")
    
    accuracy, report, y_pred = train_and_evaluate_classifier(normal_logs, suspicious_logs)
    
    print("Accuracy:", accuracy)
    print("Classification Report:\n", report)
    
    suspicious_entries = []  # Collect suspicious entries, paths, and accuracy
    for log_entry, path, predicted_label in zip(suspicious_logs, suspicious_logs_paths, y_pred):
        if predicted_label == 1:  # Suspicious
            print("Suspicious Log Entry in File:", path)
            print(log_entry)
            print("Predicted Label:", predicted_label)
            # Extract relevant data from the log entry (e.g., IP addresses, URLs, error codes)
            relevant_data = extract_relevant_data(log_entry)
            suspicious_entries.append({'log_entry': log_entry, 'path': path, 'accuracy': accuracy})
    
    return {'suspicious_entries': suspicious_entries, 'accuracy': accuracy}

#________________________

#SCA Benchmark - CYRIL OAKS
#________________________
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        return result.strip()
    except subprocess.CalledProcessError as e:
        return e.output.strip()


def write_results_to_csv(results, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['Command', 'Result', 'Status'])
        csv_writer.writerows(results)


def analyze_security_results(results):
    security_issues = []

    for cmd_name, _, status in results:
        security_issues.append((cmd_name, status))

    return security_issues

def security_comms():
    security_commands = [
        ("Check for open ports", "nmap -sT -p 1-65535 localhost", "FAIL" if "open" in run_command("nmap -sT -p 1-65535 localhost") else "PASS"),
        ("Check for open services", "netstat -tuln", "FAIL" if "LISTEN" in run_command("netstat -tuln") else "PASS"),
        ("Check for installed security updates", "apt list --upgradable", "FAIL" if "upgradable" in run_command("apt list --upgradable") else "PASS"),
        ("Check for listening ports and processes", "ss -tuln", "FAIL" if "LISTEN" in run_command("ss -tuln") else "PASS"),
        ("Check for running processes", "ps aux", "FAIL" if "root" in run_command("ps aux") else "PASS"),
        ("Check for SSH configuration", "cat /etc/ssh/sshd_config", "FAIL" if "PermitRootLogin yes" in run_command("cat /etc/ssh/sshd_config") else "PASS"),
        ("Check for firewall rules", "iptables -L", "FAIL" if "DROP" in run_command("iptables -L") else "PASS"),
        ("Check for password policy", "grep 'password required pam_pwquality.so' /etc/security/pwquality.conf", "FAIL" if "minlen = 8" not in run_command("grep 'password required pam_pwquality.so' /etc/security/pwquality.conf") else "PASS"),
        ("Check for root password strength", "sudo passwd root -S", "FAIL" if "PS 19999" not in run_command("sudo passwd root -S") else "PASS"),
        ("Check for world-writable files", "find / -type f -perm -o+w", "FAIL" if run_command("find / -type f -perm -o+w") else "PASS"),
        ("Check for SUID/SGID files", "find / -type f -perm /6000", "FAIL" if run_command("find / -type f -perm /6000") else "PASS"),
        ("Check for users with empty passwords", "awk -F: '$2 == \"\" {print $1}' /etc/shadow", "FAIL" if run_command("awk -F: '$2 == \"\" {print $1}' /etc/shadow") else "PASS"),
        ("Check for unauthorized users", "awk -F: '($3 < 1000) {print $1}' /etc/passwd", "FAIL" if run_command("awk -F: '($3 < 1000) {print $1}' /etc/passwd") else "PASS"),
        ("Check for expired user passwords", "chage -l `awk -F: '($3 > 999) {print $1}' /etc/passwd`", "FAIL" if "Password expires" not in run_command("chage -l `awk -F: '($3 > 999) {print $1}' /etc/passwd`") else "PASS"),
        ("Check for world-writable directories", "find / -type d -perm -o+w", "FAIL" if run_command("find / -type d -perm -o+w") else "PASS"),
        ("Check for unauthorized SSH keys", "ls -l /home | grep -v authorized_keys | grep -v /root/.ssh", "FAIL" if run_command("ls -l /home | grep -v authorized_keys | grep -v /root/.ssh") else "PASS"),
        ("Check for unattended-upgrades status", "dpkg-reconfigure --frontend=noninteractive unattended-upgrades -p | grep 'is enabled'", "FAIL" if "Yes" not in run_command("dpkg-reconfigure --frontend=noninteractive unattended-upgrades -p | grep 'is enabled'") else "PASS"),
        ("Check for NTP service status", "systemctl is-enabled ntp", "FAIL" if "enabled" not in run_command("systemctl is-enabled ntp") else "PASS"),
        ("Check for SELinux status", "sestatus", "FAIL" if "enabled" in run_command("sestatus") else "PASS"),
        ("Check for UFW (Uncomplicated Firewall) status", "ufw status | grep -i 'Status: active'", "FAIL" if "Status: active" not in run_command("ufw status | grep -i 'Status: active'") else "PASS"),
        ("Check for AppArmor status", "apparmor_status", "FAIL" if "profiles are loaded" not in run_command("apparmor_status") else "PASS"),
        ("Check for system logs for failed login attempts", "grep 'Failed password' /var/log/auth.log", "FAIL" if run_command("grep 'Failed password' /var/log/auth.log") else "PASS"),
        ("Check for open NFS shares", "showmount -e localhost", "FAIL" if "exports list on localhost" in run_command("showmount -e localhost") else "PASS"),
        ("Check for open FTP ports", "netstat -tuln | grep -E '21|20'", "FAIL" if "LISTEN" in run_command("netstat -tuln | grep -E '21|20'") else "PASS"),
        ("Check for open SMTP ports", "netstat -tuln | grep -E '25|587|465'", "FAIL" if "LISTEN" in run_command("netstat -tuln | grep -E '25|587|465'") else "PASS"),
        ("Check for open HTTP ports", "netstat -tuln | grep -E '80|443'", "FAIL" if "LISTEN" in run_command("netstat -tuln | grep -E '80|443'") else "PASS"),
        ("Check for open database ports", "netstat -tuln | grep -E '3306|5432'", "FAIL" if "LISTEN" in run_command("netstat -tuln | grep -E '3306|5432'") else "PASS"),
        ("Check for open DNS ports", "netstat -tuln | grep -E '53|5353'", "FAIL" if "LISTEN" in run_command("netstat -tuln | grep -E '53|5353'") else "PASS"),
        ("Check for open RPC ports", "netstat -tuln | grep -E '111|2049'", "FAIL" if "LISTEN" in run_command("netstat -tuln | grep -E '111|2049'") else "PASS"),
        ("Check for open LDAP ports", "netstat -tuln | grep -E '389|636'", "FAIL" if "LISTEN" in run_command("netstat -tuln | grep -E '389|636'") else "PASS"),
        ("Check for open VNC ports", "netstat -tuln | grep -E '5900|5901|5902'", "FAIL" if "LISTEN" in run_command("netstat -tuln | grep -E '5900|5901|5902'") else "PASS"),
        # Add more security commands as needed
    ]

    security_results = []
    
    
    for cmd_name, cmd, status in security_commands:
        result = run_command(cmd)
        security_results.append((cmd_name, result, status))

    output_file = "security_results.csv"
    write_results_to_csv(security_results, output_file)
    print(f"Security results saved to {output_file}")

    return security_results

def run_sca_benchmark():
    security_results = security_comms()

    security_issues = analyze_security_results(security_results)
    list_of_issues = []
    if security_issues:
        print("\nSecurity Issues:")
        for cmd, status in security_issues:
            list_of_issues.append(f"{cmd}: {status}")

    return list_of_issues