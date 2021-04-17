#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter='net 10.0.2.0/24', prn=print_pkt)