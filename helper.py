import scapy.all
from packet import TCPPacket, UDPPacket, ICMPPacket, ARPPacket
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.http import HTTP                                         # TCP
from scapy.layers.dhcp import DHCP                                         # UDP                            # UDP
from scapy.layers.hsrp import HSRP                                         # TCP
from scapy.layers.llmnr import LLMNRQuery,LLMNRResponse                    # TCP
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse       # TCP
from scapy.layers.ntp import NTP                                           # TCP
from scapy.layers.radius import Radius                                     # TCP
from scapy.layers.rip import RIP                                           # TCP
from scapy.layers.smb import SMBNetlogon_Protocol_Response_Header          # TCP
from scapy.layers.smb2 import SMB2_Header                                  # TCP
from scapy.layers.snmp import SNMP                                         # TCP
from scapy.layers.tftp import TFTP                                         # TCP

HTTP_REQUEST_PACKET = "HTTP_REQUEST"
HTTP_RESPONSE_PACKET = "HTTP_RESPONSE"
DNS_QUERY_PACKET = "DNS_QUERY"
DNS_ANSWER_PACKET = "DNS_ANSWER"
DHCP_PACKET = "DHCP"
HSRP_PACKET = "HSRP"
LLMNR_QUERY_PACKET = "LLMNR_Query"
LLMNR_RESPONSE_PACKET = "LLMNR_Response"
NBNS_QUERY_PACKET = "NBNS_Query"
NBNS_RESPONSE_PACKET = "NBNS_Response"
TCP_PACKET = "TCP"
UDP_PACKET = "UDP"

tcpSessions = []
udpSessions = []
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
    """
    If we got a packet the is the same but to the opposite side, skip.
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
    """
    Checks if there is an active session in a lower layer,
    If exsists - returns True else False.

    Args:
        sessions ([{},{}]): active TCP/UDP sessions
        data (string): the current packet

    Returns:
        _type_: BOOL (True/False)
    """
    for session in sessions:
        if session["destinationIP"] == data["destinationIP"] or \
            session["soruceIP"] == data["soruceIP"] and \
                session["sourcePort"] == data["sourcePort"] or \
                    session["destinationPort"] == data["destinationPort"]:
                        return True
    
    return False


def parse(pcap):
    pkts = scapy.all.rdpcap(pcap)

    for packet in pkts:
        # Layer 3 and above
        if IP in packet:
            if UDP in packet:
                packetType = UDP_PACKET
                udpData = getUDPPacketInfo(packet)
                udpPacket = UDPPacket(udpData,UDP_PACKET)

                # UDP Packet
                if DNS in packet:
                    if "Qry" in packet[DNS].mysummary():
                        packetType = DNS_QUERY_PACKET
                    else:
                        packetType = DNS_ANSWER_PACKET

                # DHCP Packet
                elif DHCP in packet:
                    packetType = DNS_QUERY_PACKET
                
                # HSRP Packet
                elif HSRP in packet:
                    packetType = HSRP_PACKET
                
                # LLMNR Packet
                elif LLMNRQuery in packet or LLMNRResponse in packet:
                    if LLMNRQuery in packet:
                        packetType = LLMNR_QUERY_PACKET
                    else:
                        packetType = LLMNR_RESPONSE_PACKET

                # NetBIOS Packet
                elif NBNSQueryRequest in packet or NBNSQueryResponse in packet:
                    if NBNSQueryRequest in packet:
                        packetType = NBNS_QUERY_PACKET
                    else:
                        packetType = NBNS_RESPONSE_PACKET

                udpPacket = UDPPacket(udpData,packetType)
                if not compareLayer4Session(udpSessions,udpData):
                    udpPacket.addNodes()

                udpSessions.append(udpData)   

            
            elif TCP in packet:
                packetType = TCP_PACKET
                tcpData = getTCPPacketInfo(packet)
                tcpPacket = TCPPacket(tcpData,TCP_PACKET)
                if HTTP in packet:
                    if httpReq in str(packet[HTTP]).split()[0]:
                        packetType = HTTP_RESPONSE_PACKET    
                    else:
                        packetType = HTTP_REQUEST_PACKET

                    tcpPacket = TCPPacket(tcpData,packetType)
                        

                if TCP_PACKET != packetType:
                    if compareLayer4Relation(tcpSessions,tcpData):
                        tcpPacket.updateRelation(packetType, TCP_PACKET)
                    
                if not compareLayer4Session(tcpSessions,tcpData):
                    tcpPacket.addNodes()

                tcpSessions.append(tcpData)

            elif ICMP in packet:
                icmpData = getICMPacketInfo(packet)
                icmpPacket = ICMPPacket(icmpData)
                icmpPacket.addNodes()

        # Layer 2 or IPV6
        else:
            if ARP in packet:
                arpData = getARPacketInfo(packet)
                arpPacket = ARPPacket(arpData)
                arpPacket.addNodes()