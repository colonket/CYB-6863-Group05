#!/usr/bin/env python3
# Preparation Phase - Asset Inventory Script
import os
import psutil
import subprocess
import re

def main():
    get_active_users()
    get_software_info()
    get_security_patches()
    get_auto_runs()
    get_usb_history()


# List all active users on a system
def get_active_users():
    pass

# Identify installed software and versions
def get_software_info():
    pass

# Check for missing security patches
def get_security_patches():
    pass

# List auto runs
def get_auto_runs():
    autoruns = []

    # Common directories for autostart entries
    autostart_dirs = [
        os.path.expanduser("~/.config/autostart"),  # User-specific autostart
        "/etc/xdg/autostart",  # System-wide autostart
        "/etc/init.d",  # Init.d scripts
        "/lib/systemd/system",  # Systemd units
    ]

    for dir in autostart_dirs:
        if os.path.exists(dir):
            for entry in os.listdir(dir):
                autoruns.append(os.path.join(dir, entry))

    # Check cron jobs
    cron_jobs = ["/etc/crontab", "/etc/cron.d"]
    for job in cron_jobs:
        if os.path.exists(job):
            autoruns.append(job)

    # List running services (optional)
    for service in psutil.win_service_iter():
        autoruns.append(service.name())

    for autorun in autoruns:
        print(autorun)

    return autoruns

# Identify USB History
def get_usb_history():
    usb_history = []

    # Run dmesg command to get kernel messages
    try:
        dmesg_output = subprocess.check_output(['dmesg'], stderr=subprocess.STDOUT).decode('utf-8')
    except subprocess.CalledProcessError as e:
        print("Error running dmesg: ", e.output.decode('utf-8'))
        return []

    # Regular expression to find USB events
    usb_event_pattern = re.compile(r'(usb\s+\d+-\d+:\d+|new\s+high-speed\s+USB\s+device\s+number\s+\d+)')
    
    for line in dmesg_output.splitlines():
        if usb_event_pattern.search(line):
            usb_history.append(line.strip())

    for event in usb_history:
        print(event)

    return usb_history

if __name__ == __main__:
    main()
