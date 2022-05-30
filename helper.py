from traceback import print_exception
import scapy.all
from packet import TCPPacket, UDPPacket, ICMPPacket, ARPPacket
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, UDP, ICMP, IP

tcpSessions = dict()
udpSession = dict()

def getTCPPacketInfo(packet):
    srcIP = packet[IP].src
    dstIP = packet[IP].dst
    srcPort = packet[TCP].sport
    dstPort = packet[TCP].dport
    srcMac = packet['Ether'].src
    dstMac = packet['Ether'].dst
    return {
     "soruceIP" : srcIP,
     "destinationIP" : dstIP, 
     "sourcePort" : srcPort, 
     "destinationPort" : dstPort,
     "sourceMac" : srcMac,
     "destinationMac" : dstMac
    }

def getUDPPacketInfo(packet):
    srcIP = packet[IP].src
    dstIP = packet[IP].dst
    srcPort = packet[UDP].sport
    dstPort = packet[UDP].dport
    srcMac = packet['Ether'].src
    dstMac = packet['Ether'].dst
    return {
     "soruceIP" : srcIP,
     "destinationIP" : dstIP, 
     "sourcePort" : srcPort, 
     "destinationPort" : dstPort,
     "sourceMac" : srcMac,
     "destinationMac" : dstMac
    }

def getICMPacketInfo(packet):
    srcIP = packet[IP].src
    dstIP = packet[IP].dst
    srcMac = packet['Ether'].src
    dstMac = packet['Ether'].dst
    return {
     "soruceIP" : srcIP,
     "destinationIP" : dstIP,
     "sourceMac" : srcMac,
     "destinationMac" : dstMac
    }

def getARPacketInfo(packet):
    srcMac = packet['Ether'].src
    dstMac = packet['Ether'].dst
    return {
     "sourceMac" : srcMac,
     "destinationMac" : dstMac
    }

def parse(pcap):
    pkts = scapy.all.rdpcap(pcap)

    for packet in pkts:
        # Layer 3 and above
        if IP in packet:
            if UDP in packet:
                udpData = getUDPPacketInfo(packet)
                udpPacket = UDPPacket(udpData)
                udpPacket.addNodes()
            
            elif TCP in packet:
                tcpData = getTCPPacketInfo(packet)
                tcpPacket = TCPPacket(tcpData)
                tcpPacket.addNodes()

            elif ICMP in packet:
                icmpData = getICMPacketInfo(packet)
                icmpPacket = ICMPPacket(icmpData)
                icmpPacket.addNodes()

        # Layer 2
        else:
            if ARP in packet:
                arpData = getARPacketInfo(packet)
                arpPacket = ARPPacket(arpData)
                arpPacket.addNodes()