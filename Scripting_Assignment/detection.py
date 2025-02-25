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
blocked_ips = set() # IPs blocked by IP tables, because it exceeded threshhold

def analyze_logs():
    while True:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    # Regex to extract IP and login status (adapt to your log format)
                    match = re.search(r".*(Failed|failure|invalid) password.*from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line, re.IGNORECASE)
                    if match:
                        ip = match.group("ip")
                        failed_attempts[ip].append(time.time())

                        # Check for threshold
                        now = time.time()
                        recent_attempts = [t for t in failed_attempts[ip] if now - t < time_window]
                        failed_attempts[ip] = recent_attempts  # Keep only recent attempts
                        if (len(recent_attempts) >= threshold) and (ip not in blocked_ips):
                            print(f"ALERT: Potential brute-force attack from IP: {ip}")
                            # You could add code here to block the IP (Bonus Challenge)
                            # Block the IP (iptables example - requires root privileges)
                            try:
                                subprocess.run(["sudo","iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)  # Adapt to your needs
                                print(f"IP {ip} blocked.")
                                blocked_ips.add(ip)
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
    while True:
        try:
            # Run ausearch command to get root login events
            output = subprocess.check_output(['sudo', 'ausearch', '-k', 'login_events', '-ua', '0'], stderr=subprocess.STDOUT).decode('utf-8')
            for line in output.splitlines():
                print(f"Privileged login detected: {line.strip()}")
            
            time.sleep(5)
        
        except subprocess.CalledProcessError as e:
            print("Error running ausearch: ", e.output.decode('utf-8'))
            return
            
if __name__ == "__main__":
    analyze_logs()
    monitor_privileged_logins()
