#!/usr/bin/env python3

import time
import socket
import binascii
from struct import *
from scapy.all import *

SOCK_PATH         = "/tmp/dpisocket"

sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
sock.connect(SOCK_PATH)

load_layer("http")

packets = [Ether()/IP(src='130.192.10.29', dst='130.192.10.28')/TCP(sport=9999,dport=8886,flags='S'),
            Ether()/IP(src='130.192.10.28', dst='130.192.10.29')/TCP(sport=8886,dport=9999,flags='SA'),
            Ether()/IP(src='130.192.10.29', dst='130.192.10.28')/TCP(sport=9999,dport=8886,flags='A'),
            Ether()/IP(src='130.192.10.29', dst='130.192.10.28')/TCP(sport=9999,dport=8886,flags='PA')/'GET / HTTP/1.0\r\nHOST: www.test.com\r\n\r\n',
            Ether()/IP(src='130.192.10.28', dst='130.192.10.29')/TCP(sport=8886,dport=9999,flags='A')/'200 OK\r\n\r\n',
            Ether()/IP(src='130.192.10.29', dst='130.192.10.28')/ICMP()
          ]

for p in packets:
    sock.sendall(bytes(p))
    data = sock.recv(1024)
    print('Received', repr(data))

#packets = rdpcap('trace.pcap')
#for p in packets:
    #s.sendall(bytes(p))
    #data = s.recv(1024)
    #print('Received', repr(data))

