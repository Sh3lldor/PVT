import scapy.all
from packet import TCPPacket, UDPPacket, ICMPPacket, ARPPacket
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.http import HTTP                                  # TCP
from scapy.layers.dhcp import DHCP                                  # UDP
from scapy.layers.dhcp6 import DHCP6                                # UDP
from scapy.layers.hsrp import HSRP                                  # TCP
from scapy.layers.llmnr import LLMNRQuery,LLMNRResponse             # TCP
from scapy.layers.netbios import NetBIOS_DS                         # TCP
from scapy.layers.ntp import NTP                                    # TCP
from scapy.layers.radius import Radius                              # TCP
from scapy.layers.rip import RIP                                    # TCP
from scapy.layers.smb import SMBNetlogon_Protocol_Response_Header   # TCP
from scapy.layers.smb2 import SMB2_Header                           # TCP
from scapy.layers.snmp import SNMP                                  # TCP
from scapy.layers.tftp import TFTP                                  # TCP
import re

HTTP_REQUEST_PACKET = "HTTP_REQUEST"
HTTP_RESPONSE_PACKET = "HTTP_RESPONSE"
TCP_PACKET = "TCP"
UDP_PACKET = "UDP"

tcpSessions = []
udpSession = dict()
httpReq = "HTTP"

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

def compareLayer4Session(sessions,data):
    """If we got a packet the is the same but to the opposite side, skip.
       This will filter TCP/UDP sessions.

    Args:
        packetType (string): the packet type
        data (string): packet layer4 dict data

    Returns:
        _type_: BOOL (True/False)
    """
    for session in sessions:
        if session["destinationIP"] == data["soruceIP"] and \
            session["soruceIP"] == data["destinationIP"] and \
                session["sourcePort"] == data["destinationPort"] and \
                    session["destinationPort"] == data["sourcePort"]:
                        return True
    
    return False


def compareLayer4Relation(sessions,data):
    for session in sessions:
        if session["destinationIP"] == data["destinationIP"] or \
            session["soruceIP"] == data["soruceIP"] and \
                session["sourcePort"] == data["sourcePort"] or \
                    session["destinationPort"] == data["destinationPort"]:
                        print(session)
        if session["destinationIP"] == data["destinationIP"] or \
            session["soruceIP"] == data["soruceIP"] and \
                session["sourcePort"] == data["sourcePort"] or \
                    session["destinationPort"] == data["destinationPort"]:
                        print("True")
                        return True
    
    return False


def parse(pcap):
    pkts = scapy.all.rdpcap(pcap)

    for packet in pkts:
        # Layer 3 and above
        if IP in packet:
            if UDP in packet:
                udpData = getUDPPacketInfo(packet)
                udpPacket = UDPPacket(udpData,"udp")
                udpPacket.addNodes()
            
            elif TCP in packet:
                packetType = TCP_PACKET
                tcpData = getTCPPacketInfo(packet)
                tcpPacket = TCPPacket(tcpData,TCP_PACKET)
                if HTTP in packet:
                    if httpReq in str(packet[HTTP]).split()[0]:
                        tcpPacket = TCPPacket(tcpData,HTTP_RESPONSE_PACKET)
                        packetType = HTTP_RESPONSE_PACKET
                    else:
                        tcpPacket = TCPPacket(tcpData,HTTP_REQUEST_PACKET)
                        packetType = HTTP_REQUEST_PACKET

                if TCP_PACKET != packetType:
                    print("DIFF ", packetType)
                    if compareLayer4Relation(tcpSessions,tcpData):
                        print()
                        tcpPacket.updateRelation(packetType, TCP_PACKET)
                    
                if not compareLayer4Session(tcpSessions,tcpData):
                    tcpPacket.addNodes()

                tcpSessions.append(tcpData)

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