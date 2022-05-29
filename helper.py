import scapy.all
from packet import TCPPacket, UDPPacket
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, UDP, ICMP, IP

sessions = dict()

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

def parse(pcap):
    pkts = scapy.all.rdpcap(pcap)

    for packet in pkts:
        if IP in packet:
            if TCP in packet:
                tcpData = getTCPPacketInfo(packet)
                tcpPacket = TCPPacket(
                    tcpData['sourceMac'],
                    tcpData['destinationMac'],
                    tcpData['soruceIP'],
                    tcpData['destinationIP'],
                    tcpData['sourcePort'],
                    tcpData['destinationPort']
                )
                #print(tcpPacket.getSourceIp() ," -> ", tcpPacket.getDestinationIp())
            
            elif UDP in packet:
                udpData = getUDPPacketInfo(packet)
                udpPacket = UDPPacket(
                    udpData['sourceMac'],
                    udpData['destinationMac'],
                    udpData['soruceIP'],
                    udpData['destinationIP'],
                    udpData['sourcePort'],
                    udpData['destinationPort']
                )

                if udpPacket.getSourceIp() not in sessions:
                    udpPacket.addNodesToGraph(udpPacket.getSourceIp(),udpPacket.getSourceMac())
                    sessions[udpPacket.getSourceIp()] = udpPacket

                elif udpPacket.getDestinationIp() not in sessions:
                    udpPacket.addNodesToGraph(udpPacket.getDestinationIp(),udpPacket.getDestinationMac())
                    sessions[udpPacket.getDestinationIp()] = udpPacket





