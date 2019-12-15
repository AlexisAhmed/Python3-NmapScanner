#!/usr/bin/python3
import nmap
import collections

scanner = nmap.PortScanner()
ScanType = collections.namedtuple("ScanType", "proto args")
scan_types = {
    1: ScanType(proto="tcp", args="-v -sS"),
    2: ScanType(proto="udp", args="-v -sU"),
    3: ScanType(proto="tcp", args="-v -sS -sV -sC -A -O")
}

print("Welcome, this is a simple nmap automation tool")
print("<", ">", sep="-" * 45)

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)

resp = int(input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n"""))
print("You have selected option: ", resp)

if resp in scan_types:
    scan_type = scan_types[resp]
    "Nmap Version: ", scanner.nmap_version()
    scanner.scan(ip_addr, '1-1024', scan_type.args)
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print("Protocols: ", ", ".join(scanner[ip_addr].all_protocols()))
    print("Open Ports: ", ", ".join(str(p) for p in scanner[ip_addr][scan_type.proto].keys()))
else:
    print("Please enter a valid option")
