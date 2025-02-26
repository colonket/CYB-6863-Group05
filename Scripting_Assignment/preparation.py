#!/usr/bin/env python3
# Preparation Phase - Asset Inventory Script
# Operating System: Linux
import os
import psutil
import subprocess
import re
import argparse

def main():
    parser = argparse.ArgumentParser(description='How to use our script')
    parser.add_argument("-a", "--active-users", action='store_true', help="List all active users")
    parser.add_argument("-s", "--software-info",action='store_true',help="Identify installed software and versions")
    parser.add_argument("-p", "--security-patches",action='store_true',help="Check for missing security patches")
    parser.add_argument("-r", "--auto-runs",action='store_true',help="List processes that automatically run")
    parser.add_argument("-u", "--usb-history",action='store_true',help="List USB Device history")
    parser.add_argument("--all",action='store_true',help="Runs all options")
    args = parser.parse_args()

    if args.active_users:
        get_active_users()
    if args.software_info:
        get_software_info()
    if args.security_patches:
        get_security_patches()
    if args.auto_runs:
        get_auto_runs()
    if args.usb_history:
        get_usb_history()
    if args.all:
        get_active_users()
        get_software_info()
        get_security_patches()
        get_auto_runs()
        get_usb_history()

# List all active users on a system
def get_active_users():
    print("=== Active Users on the System ===")
    users = psutil.users()
    for user in users:
        print(user.name)  # print username

# Identify installed software and versions
def get_software_info():

    #runs commands to collect info
    def run_cmd(cmd, skip_header=False, split_by=None):
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
            lines = result.split("\n")
            if skip_header:
                lines = lines[1:]  # Skip first line (e.g., Snap header)
            return [line.split(split_by)[:2] for line in lines[:10]] if split_by else lines[:10]
        except:
            return []

    #displays info
    print("\n=== System Information ===")
    system_info = run_cmd(["lsb_release", "-d"])
    print(system_info[0] if system_info else "Unknown")

    print("\n=== Installed APT Packages ===")
    apt_packages = run_cmd(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], split_by=" ")
    for pkg in apt_packages:
        print(f"{pkg[0]} - {pkg[1]}" if len(pkg) > 1 else pkg[0])
    print(f"...({len(apt_packages)} packages total)")

# Check for missing security patches
def get_security_patches():
    print("=== Get Security Patches ===")

    #updates then checks if security updates need to be upgraded
    try:
        subprocess.run(["sudo", "apt", "update"], check=True)
        updates = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True, check=True).stdout
        security_updates = [line for line in updates.split("\n") if "security" in line]

        #then it will/won't upgrade accordingly
        if security_updates:
            print("Applying security updates...")
            subprocess.run(["sudo", "apt", "upgrade", "-y"], check=True)
        else:
            print("No security updates available.")
            
    #in case it errors out
    except subprocess.CalledProcessError as e:
        print(f"Error updating system: {e}")

# List auto runs
def get_auto_runs():
    print("=== List Auto Runs ===")
    autoruns = []

    # directories for autostart entries
    autostart_dirs = [
        os.path.expanduser("~/.config/autostart"),  # user specific autostart
        "/etc/xdg/autostart",  # systemwide autostart
        "/etc/init.d",  # init.d scripts
        "/lib/systemd/system",  # Systemd units
    ]

    for dir in autostart_dirs:
        if os.path.exists(dir):
            for entry in os.listdir(dir):
                autoruns.append(os.path.join(dir, entry))

    # checking cron jobs
    cron_jobs = ["/etc/crontab", "/etc/cron.d"]
    for job in cron_jobs:
        if os.path.exists(job):
            autoruns.append(job)

    # list running services (optional)
    #for service in psutil.service_iter():
    #    autoruns.append(service.name())

    for autorun in autoruns:
        print(autorun)

    return autoruns

# identify USB History
def get_usb_history():
    print("=== Identify USB History ===")
    usb_history = []

    # Run dmesg command to get kernel messages
    try:
        dmesg_output = subprocess.check_output(['sudo','dmesg'], stderr=subprocess.STDOUT).decode('utf-8')
    except subprocess.CalledProcessError as e:
        print("Error running dmesg: ", e.output.decode('utf-8'))
        return []

    # regular expression to find USB events
    usb_event_pattern = re.compile(r'(usb\s+\d+-\d+:\d+|new\s+high-speed\s+USB\s+device\s+number\s+\d+)')
    
    for line in dmesg_output.splitlines():
        if usb_event_pattern.search(line):
            usb_history.append(line.strip())

    for event in usb_history:
        print(event)

    return usb_history

if __name__ == "__main__":
    main()
