#!/usr/bin/env python

import scapy.all as scapy
# Python3 version of optparse
import argparse


def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="Target IP / IP Range to search")
    (options) = parser.parse_args()
    return options


def scan(ip):
    # Use .show() to look at packet info in 'english'
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # in Scapy can append packets with /
    arpRequestBroadcast = broadcast/arpRequest
    # without timeout - will wait for response indef.
    # returns list, so add [0] to capture only the first element of list
    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]
    clientList = []
    for element in answeredList:
        clientDict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clientList.append(clientDict)
    return clientList


def printResult(resultList):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in resultList:
        print(client["IP"] + "\t\t" + client["MAC"])


target = getArguments()
result = scan(target.ip)
printResult(result)