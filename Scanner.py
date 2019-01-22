#!/usr/bin/python3

# run with sudo Python3 Scanner.py

# pip3 install python-nmap
import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<-------------------------------------------------------->")
print("Currently installed nmap version: ", scanner.nmap_version())
print("<-------------------------------------------------------->")

ip_addr = '127.0.0.1'  # default ip address
prompt_str = "Please enter the IP address you want to scan ["+ip_addr+"]: "
ip_addr = input(prompt_str) or ip_addr
print("Selected IP: ", ip_addr)
type(ip_addr)

resp = input("""\nEnter the scan type you want to run
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan \n""")
print("You have selected option: ", resp)


def run_scan(args: str, port_range: str = '1-1024'):
    scanner.scan(ip_addr, port_range, args)
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    protocols = scanner[ip_addr].all_protocols()
    print(protocols)
    for protocol in protocols:
        print("["+protocol+"] open ports: ", scanner[ip_addr][protocol].keys())


# -v verbose
if resp == '1':
    # -sS TCP SYN scan
    run_scan('-v -sS')
elif resp == '2':
    # -sU UDP SYN scan
    run_scan('-v -sU')
elif resp == '3':
    # -sS TCP SYN scan
    # -sV Version detection
    # -sC script scan using the default set of scripts
    # -A Aggressive scan options
    # -O Enable OS detection
    run_scan('-v -sS -sV -sC -A -O')
else:
    print("Please enter a valid option")
