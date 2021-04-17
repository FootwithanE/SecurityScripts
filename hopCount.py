#!usr/bin/python

from scapy.all import *
import argparse

def getArgument():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="ip")
	(options) = parser.parse_args()
	return options

def sendPckt(target):
	hops = 1
	success = "echo-reply"
	failure = "dest-unreach"
	hopList = []
	ipHdr = IP()
	payload = ICMP()
	ipHdr.dst = target
	ipHdr.ttl = hops
	while True:
		pkt = ipHdr/payload
		resp = sr1(pkt)
		hopList.append({"IP": resp[IP].src, "NUM": hops})
		if success in str(resp[ICMP].summary()):
			return hopList
		elif failure in str(resp[ICMP].summary()):
			print("Unable to reach network!")
			break;
		else:
			hops+=1
			ipHdr.ttl = hops

def printTraceRT(list):
	if list:
		print("IP\t\t\tHop Number\n-----------------------------------")
		for router in list:
			print(str(router["IP"]) + "\t\t\t" + str(router["NUM"]))

target = getArgument()
table = sendPckt(target.ip)
printTraceRT(table)