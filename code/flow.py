#!/usr/bin/env python
import sys
import struct
import os
import argparse
import socket
import random
import argparse
import time
import gpt2

from scapy.all import sniff, send, sendp, hexdump, get_if_list, get_if_hwaddr, hexdump, sr1,sr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, IPv6, TCP, UDP, Raw, Ether
from scapy.layers.inet import _IPOption_HDR
from gpt2 import *
from scapy import all

class dl_pdu_session(Packet):
    name = "DL PDU Session"
	fields_desc = [ BitField("gtp_ext", 0,8),
                BitField("PDU_type",0,4),
                BitField("Spare",0,5),
                BitField("RQI",0,1),
                BitField("QoSID",0,6),
                BitField("padding",0,8),
                ]

def main():
    bind_layers(GTP_U_Header, dl_pdu_session, E = 1 )

    pkt5g =  Ether(src='00:15:5d:00:00:00', dst='00:15:5d:00:00:04') / IPv6(src="fc00::1", dst="fc00::5") /  IPv6ExtHdrRouting(type = 4, segleft = 2, addresses=["fc00::5","fc00::101","fc00::100"]) / UDP (sport=64515, dport=2152 ) / GTP_U_Header(TEID=32, Reserved=0, E=1) / dl_pdu_session(gtp_ext=133,QoSID=14,Spare=2) / IPv6(src="fc10::2", dst="fc20::2") / ICMPv6EchoRequest()

    sendp(pkt5g, iface="enp0s10", verbose=False)

if __name__ == '__main__':
    main()