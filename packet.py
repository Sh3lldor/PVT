import abc
from inspect import getsource
import graph

class Packet:
    @abc.abstractmethod
    def __init__(self,sourceMac,destinationMac):
        self.srcMac = sourceMac
        self.dstMac = destinationMac

    def getSourceMac(self):
        return self.srcMac
    
    def getDestinationMac(self):
        return self.dstMac


class TCPPacket(Packet):
    def __init__(self,sourceMac,destinationMac,soruceIP,destinationIP,sourcePort,destinationPort):
        super().__init__(sourceMac, destinationMac)
        self.srcIP = soruceIP
        self.dstIP = destinationIP
        self.srcPort = sourcePort
        self.dstPort = destinationPort

    def getSourceIp(self):
        return self.srcIP
    
    def getDestinationIp(self):
        return self.dstIP

    def getSourcePort(self):
        return self.srcPort

    def getDestinationPort(self):
        return self.dstPort


class UDPPacket(Packet):
    def __init__(self,sourceMac,destinationMac,soruceIP,destinationIP,sourcePort,destinationPort):
        super().__init__(sourceMac, destinationMac)
        self.srcIP = soruceIP
        self.dstIP = destinationIP
        self.srcPort = sourcePort
        self.dstPort = destinationPort

    def getSourceIp(self):
        return self.srcIP
    
    def getDestinationIp(self):
        return self.dstIP

    def getSourcePort(self):
        return self.srcPort

    def getDestinationPort(self):
        return self.dstPort

    def getAll(self):
        print(self.srcIP, "-> ", self.dstIP, "|", self.srcPort,"-> " ,self.dstPort, self.srcMac, " -> ", self.dstMac)

    def addNodesToGraph(self, ip, mac):
        graph.addServerNode(ip,mac)
        

    