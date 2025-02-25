#!/usr/bin/env python3
# Detection Phase - Suspicious Login Monitoring
import time
import re
import subprocess

def monitor_privileged_logins():
    login_pattern = re.compile(r'USER_LOGIN.*?auid=(\d+)')

    while True:
        try:
            output = subprocess.check_output(['ausearch', '-k', 'login_events', '-i'], stderr=subprocess.STDOUT).decode('utf-8')
            
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
