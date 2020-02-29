#!/usr/bin/python3

import socket 

portas = [21, 22, 80, 8080, 443]

for porta in portas:
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientesettimeout(1.0)
    codigo = cliente.connect_ex(("IP", porta))
    if codigo == 0:
        print(porta, "OPEN")
