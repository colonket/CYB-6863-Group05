#!/usr/bin/env python3
# Detection Phase - Suspicious Login Monitoring
import time
import re
import subprocess
from collections import defaultdict

# Log file path (adjust to your system)
log_file = "/var/log/auth.log"  # Example: /var/log/auth.log on Linux

# Failed login threshold
threshold = 5
time_window = 600  # 10 minutes in seconds

# Dictionary to store failed login attempts (IP: [timestamps])
failed_attempts = defaultdict(list)

def analyze_logs():
    while True:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    # Regex to extract IP and login status (adapt to your log format)
                    match = re.search(r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*(Failed|failure|invalid) password", line, re.IGNORECASE)
                    if match:
                        ip = match.group("ip")
                        failed_attempts[ip].append(time.time())

                        # Check for threshold
                        now = time.time()
                        recent_attempts = [t for t in failed_attempts[ip] if now - t < time_window]
                        failed_attempts[ip] = recent_attempts  # Keep only recent attempts
                        if len(recent_attempts) >= threshold:
                            print(f"ALERT: Potential brute-force attack from IP: {ip}")
                            
                            # You could add code here to block the IP (Bonus Challenge)
                            # Block the IP (iptables example - requires root privileges)
                            try:
                                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)  # Adapt to your needs
                                print(f"IP {ip} blocked.")
                            except subprocess.CalledProcessError as e:
                                print(f"Error blocking IP: {e}")

            time.sleep(60)  # Check every minute
        except FileNotFoundError:
            print(f"Error: Log file '{log_file}' not found.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            break

def monitor_privileged_logins():
    login_pattern = re.compile(r'USER_LOGIN.*?auid=(\d+)')

    while True:
        try:
            output = subprocess.check_output(['sudo', 'ausearch', '-k', 'login_events', '-i'], stderr=subprocess.STDOUT).decode('utf-8')
            
            for line in output.splitlines():
                match = login_pattern.search(line)
                if match:
                    auid = int(match.group(1))
                    # Check if auid is 0 (root user)
                    if auid == 0:
                        print(f"Privileged login detected: {line.strip()}")
            
            time.sleep(5)
        
        except subprocess.CalledProcessError as e:
            print("Error running ausearch: ", e.output.decode('utf-8'))
            return
            
if __name__ == "__main__":
    analyze_logs()
    monitor_privileged_logins()
