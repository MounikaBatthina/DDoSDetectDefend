import os
from django.http import HttpResponse
from django.template import Context, loader

import dpkt
from django.shortcuts import render_to_response


def index(request):
    return HttpResponse("<h1>Detect Page</h1><td><a href='/detect/dt'>Start the detection</a></td>")

def detect_ddos(request):
    counter = 0
    ipcounter = 0
    tcpcounter = 0
    udpcounter = 0

    filename ='test1.pcap'

    for ts, pkt in dpkt.pcap.Reader(open(filename, 'rb')):

        counter += 1
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        ipcounter += 1

        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcpcounter += 1

        if ip.p == dpkt.ip.IP_PROTO_UDP:
            udpcounter += 1

    header = "Total number of packets in the pcap file: "+str(counter)+"<br>Total number of ip packets: " + str(ipcounter)+"<br>Total number of tcp packets: "+str(tcpcounter)+"<br>Total number of udp packets: " + str(udpcounter)
    return HttpResponse("<h1>Detected!<br>"+header+"</h1>")


def redirect(request):
    return HttpResponse()
