#!/usr/bin/python
import os
import shlex, subprocess
from scapy.all import *
from netfilterqueue import NetfilterQueue

ip_set = set()
iptables = "iptables -t nat -A OUTPUT -p tcp --dport 2223 -j DNAT --to {0}:22"

def process(pkt):
    global ip_set
    ip = IP(pkt.get_payload())
    if ip.dst in ip_set:
        pkt.accept()
        return

    pkt.set_mark(1)    
    os.system(iptables.format(ip.dst))
    ip_set.add(ip.dst)
    pkt.repeat()
    
nfqueue = NetfilterQueue()
nfqueue.bind(0, process)
os.system("iptables -t nat -A OUTPUT -p tcp --dport 22 -m mark --mark 0 -j NFQUEUE")
os.system("iptables -t nat -A OUTPUT -p tcp --dport 22 -j DNAT --to 127.0.0.1:2222")
proxy = subprocess.Popen(shlex.split("./mitmproxy_ssh -H 192.0.2.0 -P 2223")) #use 192.0.2.0 as IP for example

try:
    nfqueue.run()
except KeyboardInterrupt:
    proxy.terminate()
    os.system("iptables -t nat -F")
    os.system("iptables -t nat -X")
