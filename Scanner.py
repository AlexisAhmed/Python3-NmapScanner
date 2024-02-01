#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool.")
print("-------------------------------------------------")

ip_addr = input("IP: ")
print("The IP you entered is:", ip_addr)

while True:
    resp = input(
        """\nEnter the type of scan you want to run
        1) SYN ACK Scan
        2) UDP Scan
        3) Comprehensive Scan
        """
    )
    print("You have selected option:", resp)

    if resp in {'1', '2', '3'}:
        options = '-v'
        if resp == '3':
            options += ' -sV -sC -A -O'

        if resp == '1':
            scanner.scan(ip_addr, '1-1024', f'{options} -sS')
            protocol = 'TCP'
        elif resp == '2':
            scanner.scan(ip_addr, '1-1024', f'{options} -sU')
            protocol = 'UDP'
        else:
            scanner.scan(ip_addr, '1-1024', f'{options} -sS')
            protocol = 'TCP'

        print("Nmap Version:", '.'.join(map(str, scanner.nmap_version())))
        print("Scan Info:", scanner.scaninfo())
        print("IP Status:", scanner[ip_addr].state())
        print("Protocol:", protocol)
        print("Open ports:", list(scanner[ip_addr][protocol.lower()].keys()))
        break
    else:
        print("Invalid option")








