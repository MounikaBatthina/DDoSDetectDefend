from django.http import HttpResponse
import dpkt
from django.shortcuts import render_to_response


def index(request):
    return HttpResponse("<h1>Detect Page</h1>")

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

    print ("Total number of packets in the pcap file: " , counter)
    print ("Total number of ip packets: " , ipcounter)
    print ("Total number of tcp packets: " , tcpcounter)
    print ("Total number of udp packets: " , udpcounter)
    return HttpResponse("<h1>Detected!</h1>")

