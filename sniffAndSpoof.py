#!/usr/bin/python
from scapy.all import *

def sniffPacket():
	pkt = sniff(filter='icmp[icmptype] == icmp-echo', prn=spoofPacket, count=3)

def spoofPacket(pkt):
	spoofedIP = IP(dst=pkt[IP].src, src=pkt[IP].dst, ttl=90)
	spoofedPkt = spoofedIP/ICMP(seq=pkt[ICMP].seq, id=pkt[ICMP].id, type=0)/pkt[Raw].load
	send(spoofedPkt)

sniffPacket()