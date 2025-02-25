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

    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def monitor_privileged_logins():
    try:
        # Run ausearch command to get succesful  root login events
        success_output = subprocess.check_output(['sudo', 'ausearch', '-ua', '0', '-i', '-m', 'USER_LOGIN'],stderr=subprocess.STDOUT).decode('utf-8')
        print(success_output)

        if "<no_matches>" not in success_output:
            for line in success_output.splitlines():
                print(f"Privileged login detected: {line.strip()}")
        else:
            print("No successful root login events found.")
                    
        # Run lastb command to get failed root login events and print root lines
        fails_output = subprocess.check_output(['sudo', 'lastb'], stderr=subprocess.STDOUT).decode('utf-8')
        for line in fails_output.splitlines():
                if 'root' in line:
                    print(f"Failed privileged login detected: {line.strip()}")
        
    except subprocess.CalledProcessError as e:
        print("Error running ausearch: ", e.output.decode('utf-8'))
        return
            
if __name__ == "__main__":
    while True:
        monitor_privileged_logins()
        #analyze_logs()
        print("\n")
        time.sleep(60)  # Check every minute
