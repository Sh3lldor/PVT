import abc
from inspect import getsource
from graph import Graph

graph = Graph()

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
    def __init__(self,tcpData,layer4):
        super().__init__(tcpData['sourceMac'], tcpData['destinationMac'])
        self.srcIP = tcpData['soruceIP']
        self.dstIP = tcpData['destinationIP']
        self.srcPort = tcpData['sourcePort']
        self.dstPort = tcpData['destinationPort']
        self.layer4 = layer4

    def getSourceIp(self):
        return self.srcIP
    
    def getDestinationIp(self):
        return self.dstIP

    def getSourcePort(self):
        return self.srcPort

    def getDestinationPort(self):
        return self.dstPort
    
    def getLayer4(self):
        return self.layer4

    def addNodes(self,relationData):
        add4thLayerNodesToGraph(self,"AddTCPRelation",self.getLayer4(), relationData)
    
    def updateRelation(self, newRelation, oldRelation):
        update4thLayerNodesToGraph(self,"UpdateTCPRelation",oldRelation, newRelation)


class UDPPacket(Packet):
    def __init__(self,udpData,layer4):
        super().__init__(udpData['sourceMac'], udpData['destinationMac'])
        self.srcIP = udpData['soruceIP']
        self.dstIP = udpData['destinationIP']
        self.srcPort = udpData['sourcePort']
        self.dstPort = udpData['destinationPort']
        self.layer4 = layer4

    def getSourceIp(self):
        return self.srcIP
    
    def getDestinationIp(self):
        return self.dstIP

    def getSourcePort(self):
        return self.srcPort

    def getDestinationPort(self):
        return self.dstPort
    
    def getLayer4(self):
        return self.layer4
    
    def updateRelation(self, newRelation, oldRelation):
        update4thLayerNodesToGraph(self,"UpdateUDPRelation",oldRelation, newRelation)
    
    def addNodes(self,relationData):
        add4thLayerNodesToGraph(self,"AddUDPRelation",self.getLayer4(),relationData)


class ICMPPacket(Packet):
    def __init__(self,icmpData):
        super().__init__(icmpData['sourceMac'], icmpData['destinationMac'])
        self.srcIP = icmpData['soruceIP']
        self.dstIP = icmpData['destinationIP']

    def getSourceIp(self):
        return self.srcIP
    
    def getDestinationIp(self):
        return self.dstIP
    
    def addNodes(self):
        add3rdLayerNodesToGraph(self,"AddICMPRelation","ICMP")


class ARPPacket(Packet):
    def __init__(self,arpData):
        super().__init__(arpData['sourceMac'], arpData['destinationMac'])
    
    def addNodes(self):
        add2ndLayerNodesToGraph(self,"AddARPRelation","ARP")


def add4thLayerNodesToGraph(obj,query,type,relationData):
        sourceMac = obj.getSourceMac()
        destinationMac = obj.getDestinationMac()
        sourceIp = obj.getSourceIp()
        destinationIp = obj.getDestinationIp()
        sourcePort = obj.getSourcePort()
        destinationPort = obj.getDestinationPort()

        data = {
            "ip":sourceIp,
            "mac":sourceMac
            }

        graph.runQuery("AddServer",data)
        data = {
            "ip":destinationIp,
            "mac":destinationMac
            }
            
        graph.runQuery("AddServer",data)
        data = {
            "source": sourceIp, 
            "destination": destinationIp, 
            "sourcePort": sourcePort, 
            "destinationPort" : destinationPort,
            "type": type,
            "relationData": relationData
            }
            
        graph.runQuery(query,data)

def update4thLayerNodesToGraph(obj,query,oldRelation,newRelation):
        sourceIp = obj.getSourceIp()
        destinationIp = obj.getDestinationIp()

        data = {
            "source": sourceIp, 
            "destination": destinationIp, 
            "type": oldRelation,
            "newType": newRelation
            }
            
        graph.runQuery(query,data)

def add3rdLayerNodesToGraph(obj,query,type):
        sourceMac = obj.getSourceMac()
        destinationMac = obj.getDestinationMac()
        sourceIp = obj.getSourceIp()
        destinationIp = obj.getDestinationIp()

        data = {
            "ip":sourceIp,
            "mac":sourceMac
            }

        graph.runQuery("AddServer",data)
        data = {
            "ip":destinationIp,
            "mac":destinationMac
            }
            
        graph.runQuery("AddServer",data)
        data = {
            "source": sourceIp, 
            "destination": destinationIp,
            "type": type
            }

        graph.runQuery(query,data)

def add2ndLayerNodesToGraph(obj,query,type):
        sourceMac = obj.getSourceMac()
        destinationMac = obj.getDestinationMac()

        data = {
            "mac":sourceMac
            }

        graph.runQuery("AddServer",data)
        data = {
            "mac":destinationMac
            }
            
        graph.runQuery("AddServer",data)
        data = {
            "source": sourceMac, 
            "destination": destinationMac,
            "type": type
            }

        graph.runQuery(query,data)

def resetDB():
    graph.clear()