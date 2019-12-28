#!/usr/bin/env python #Using this shebang ensures Python can be found on each linux distributions.

import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<----------------------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is:", ip_addr) #Edited formatting
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan
                
Enter your option: """) #Edited formatting
print("You have selected option:", resp) #Edited formatting

if resp == '1':
    print("Nmap Version:", scanner.nmap_version()) #Edited formatting
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status:", scanner[ip_addr].state()) #Edited formatting
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys()) #Edited formatting
elif resp == '2':
    print("Nmap Version:", scanner.nmap_version()) #Edited formatting
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Ip Status:", scanner[ip_addr].state()) #Edited formatting
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['udp'].keys()) #Edited formatting
elif resp == '3':
    print("Nmap Version:", scanner.nmap_version()) #Edited formatting
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip Status:", scanner[ip_addr].state()) #Edited formatting
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys()) #Edited formatting
else: #removed elif to catch more invalid options (e.g. negative numbers, strings)
    print("Please enter a valid option")








