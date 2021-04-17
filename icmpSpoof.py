#!/usr/bin/python
from scapy.all import *
import argparse

def getArguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-src", dest="source")
	parser.add_argument("-dst", dest="destination")
	(options) = parser.parse_args()
	return options

def sendPckt(source, destination):
	ipHdr = IP()
	ipHdr.src = source
	ipHdr.dst = destination
	payLoad = ICMP()
	pkt = ipHdr/payLoad
	send(pkt)

targets = getArguments()
sendPckt(targets.source, targets.destination)
print("Source: " + targets.source + " Destination: " + targets.destination)