from re import S
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
from scapy.layers.ntp import NTP,NTPHeader                                 # TCP
from scapy.layers.radius import Radius                                     # TCP
from scapy.layers.rip import RIP                                           # TCP
from scapy.layers.smb import SMBNetlogon_Protocol_Response_Header          # TCP
from scapy.layers.smb2 import SMB2_Header                                  # TCP
from scapy.layers.snmp import SNMP                                         # TCP
from scapy.layers.tftp import TFTP                                         # TCP


# Packets
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
NTP_SYMMETRIC_PACKET = "NTP_Symmetric_Active"
NTP_SERVER_PACKET = "NTP_SERVER"
RADIUS_REQUEST_PACKET = "RADIUS_Request"
RADIUS_CHALLENGE_PACKET = "RADIUS_Challenge"
RIP_REQUEST_PACKET = "RIP_Request"
RIP_RESPONSE_PACKET = "RIP_Response"
SNMP_VERION_1_PACKET = "SNMP_v1"
SNMP_VERION_2_PACKET = "SNMP_v2"
SNMP_VERION_GENERAL_PACKET = "SNMP"
TFTP_PACKET = "TFTP"
TCP_PACKET = "TCP"
UDP_PACKET = "UDP"

# ResponseCodes
NTP_SYMMETRIC_ACTIVE_CODE = 1
NTP_SERVER_CODE           = 4
RADIUS_REQUEST_CODE       = 1
RADIUS_CHALLENGE_CODE     = 11
RIP_REQUEST_CODE          = 1
RIP_RESPONSE_CODE         = 2


tcpSessions = []
udpSessions = []
httpReq = "HTTP"

def getLayer4PacketInfo(packet,packetType):
    srcIP = packet[IP].src
    dstIP = packet[IP].dst
    srcPort = packet[packetType].sport
    dstPort = packet[packetType].dport
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

def getLayer3PacketInfo(packet):
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

def getLayer2PacketInfo(packet):
    srcMac = packet['Ether'].src
    dstMac = packet['Ether'].dst
    return {
     "sourceMac" : srcMac,
     "destinationMac" : dstMac
    }

def compareLayer4Session(sessions,data, packetType):
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
                    session["destinationPort"] == data["sourcePort"] and \
                        session["type"] == packetType:
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

                elif NTP in packet:
                    ntpMode = packet[NTPHeader].mode
                    if ntpMode == NTP_SYMMETRIC_ACTIVE_CODE:
                        packetType = NTP_SYMMETRIC_PACKET

                    elif ntpMode == NTP_SERVER_CODE:
                        packetType = NTP_SERVER_PACKET
                
                elif Radius in packet:
                    radiusCode = packet[Radius].code
                    if radiusCode == RADIUS_REQUEST_CODE:
                        packetType = RADIUS_REQUEST_PACKET

                    elif radiusCode == RADIUS_CHALLENGE_CODE:
                        packetType = RADIUS_CHALLENGE_PACKET
                
                elif RIP in packet:
                    ripCmd = packet[RIP].cmd
                    if ripCmd == RIP_REQUEST_CODE:
                        packetType = RIP_REQUEST_PACKET

                    elif ripCmd == RIP_RESPONSE_CODE:
                        packetType = RIP_RESPONSE_PACKET

                elif SNMP in packet:
                    snmpDump = packet[SNMP].show(dump=True)
                    if "v1" in snmpDump:
                        packetType = SNMP_VERION_1_PACKET
                    elif "v2" in snmpDump:
                        packetType = SNMP_VERION_2_PACKET
                    else:
                        packetType = SNMP_VERION_GENERAL_PACKET

                elif TFTP in packet:
                    filename = packet[TFTP].filename
                    packetType = TFTP_PACKET
                
                udpData = getLayer4PacketInfo(packet, UDP)
                udpData["type"] = packetType
                udpPacket = UDPPacket(udpData,packetType)

                if not compareLayer4Session(udpSessions,udpData,packetType) and \
                    not compareLayer4Relation(udpSessions,udpData):
                        udpPacket.addNodes()
                
                if UDP_PACKET != packetType:
                    if compareLayer4Relation(udpSessions,udpData):
                        udpPacket.updateRelation(packetType, UDP_PACKET)

                udpSessions.append(udpData)   

            
            elif TCP in packet:
                packetType = TCP_PACKET
                if HTTP in packet:
                    if httpReq in str(packet[HTTP]).split()[0]:
                        packetType = HTTP_RESPONSE_PACKET    
                    else:
                        packetType = HTTP_REQUEST_PACKET
                

                tcpData = getLayer4PacketInfo(packet, TCP)
                tcpData["type"] = packetType
                tcpPacket = TCPPacket(tcpData,packetType)
                        
                if TCP_PACKET != packetType:
                    if compareLayer4Relation(tcpSessions,tcpData):
                        tcpPacket.updateRelation(packetType, TCP_PACKET)
                    
                if not compareLayer4Session(tcpSessions,tcpData,packetType):
                    tcpPacket.addNodes()

                tcpSessions.append(tcpData)

            elif ICMP in packet:
                icmpData = getLayer3PacketInfo(packet)
                icmpPacket = ICMPPacket(icmpData)
                icmpPacket.addNodes()

        # Layer 2 or IPV6
        else:
            if ARP in packet:
                arpData = getLayer2PacketInfo(packet)
                arpPacket = ARPPacket(arpData)
                arpPacket.addNodes()