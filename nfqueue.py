#!/usr/bin/python
import os
from scapy.all import *
from netfilterqueue import NetfilterQueue

ip_set = set()
my_ip = "172.27.2.1"
iptables1 = "iptables -t nat -A PREROUTING -p tcp -d {0} -j DNAT --to " + my_ip + ":2222"
iptables2 = "iptables -t nat -A OUTPUT -p tcp -d " + my_ip + " --dport 2223 -j DNAT --to {0}:22"

def process(pkt):
    global ip_set
    ip = IP(pkt.get_payload())
    if ip.dst in ip_set:
        pkt.accept()
        return

    pkt.set_mark(1)    
    os.system(iptables1.format(ip.dst))
    os.system(iptables2.format(ip.dst))
    ip_set.add(ip.dst)
    pkt.repeat()
    
nfqueue = NetfilterQueue()
nfqueue.bind(0, process)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print
