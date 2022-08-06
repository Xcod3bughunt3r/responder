#!/usr/bin/env python
"""
@author    : ALIF FUSOBAR
@nickname  : Xcod3bughunt3r
@license   : MIT FUCK LICENSE
@contact   : master@itsecurity.id
"""

from socket import *

print('MSSQL Server Finder 0.2')

s = socket(AF_INET,SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
s.settimeout(2)
s.sendto('\x02',('255.255.255.255',1434))

try:
    while 1:
        data, address = s.recvfrom(8092)
        if not data:
            break
        else:
            print("===============================================================")
            print(("Host details: %s"%(address[0])))
            print((data[2:]))
            print("===============================================================")
            print("")
except:
    pass
