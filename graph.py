from neo4j import *
import os
#neoServer = "neo4j"
neoServer = "localhost"
url = os.getenv("NEO4J_URI", f"bolt://{neoServer}:7687")
username = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "test")
neo4j_version = os.getenv("NEO4J_VERSION", "4")
database = os.getenv("NEO4J_DATABASE", "PVT")

class Graph:
    def __init__(self):
        self.driver = GraphDatabase.driver(url, auth=(username, password))

    def close(self):
        self.driver.close()

    def executeWriteQuery(self,func):
        with self.driver.session() as session:
            session.write_transaction(func)

    def executeReadQuery(self,func,obj):
        with self.driver.session() as session:
            return session.read_transaction(func, obj)
    
    def clear(self):
        def clearDB(tx):
            initQuery = """ match (n) detach delete n """
            tx.run(initQuery)
        with self.driver.session() as session:
            session.write_transaction(clearDB)

    
    def isNodeExist(self,data,action):
        def getRelation(tx,d):
            dstQuery = """ MATCH  (source:endpoints), (destination:endpoints) where source.ip="%s" and destination.ip="%s" RETURN EXISTS( (source)-[:%s {destinationPort:"%s"}]-(destination) ) """ \
            % (d["source"],d["destination"],d["type"],d["destinationPort"])

            srcQuery = """ MATCH  (source:endpoints), (destination:endpoints) where source.ip="%s" and destination.ip="%s" RETURN EXISTS( (source)-[:%s {sourcePort:"%s"}]-(destination) ) """ \
            % (d["source"],d["destination"],d["type"],d["sourcePort"])
            
            resDst, resSrc = tx.run(dstQuery).value(), tx.run(srcQuery).value()
            if resDst:
                dstRes = resDst[0]
            else:
                dstRes = False
                
            if resSrc:
                srcRes = resSrc[0]
            else:
                srcRes = False

            return dstRes,srcRes

        def getNode(tx,d):
            query = """ MATCH (endpoint:endpoints) where endpoint.mac="%s" RETURN EXISTS(endpoint.ip) """ \
                % (d["mac"])
            
            res = tx.run(query).value()
            if res:
                nodeExist = res[0]
            else:
                nodeExist = True

            return nodeExist


        if action == "Relation":
            return self.executeReadQuery(getRelation,data)
        elif action == "Node":
            return self.executeReadQuery(getNode,data)


    def runQuery(self,action,data):
        def addServerNode(tx):
            if "ip" in data.keys():
                if not self.isNodeExist(data,"Node"):
                    q = """ MATCH (endpoint:endpoints {mac:"%s"}) SET endpoint.ip="%s" """ % (data["mac"],data["ip"])
                else:
                    q = """ MERGE (endpoint:endpoints {ip:"%s",mac:"%s"}) """ % (data["ip"],data["mac"])
            else:
                q = """ MERGE (endpoint:endpoints {mac:"%s"}) """ % (data["mac"])
                
            tx.run(q)
            
        
        def addOneSidedRelation(tx):
            asDest, asSrc = self.isNodeExist(data,"Relation")
            if not asDest and not asSrc:
                q = """ match (source:endpoints), (destination:endpoints) WHERE source.ip="%s" AND destination.ip="%s" MERGE (source)-[r:%s {sourcePort:"%s",destinationPort:"%s",data:"%s"}]->(destination) return type(r) """ \
                % (data["source"],data["destination"],data["type"],data["sourcePort"],data["destinationPort"],data["relationData"])
                tx.run(q)

        def addTwoSidedRelation(tx):
            asDest, asSrc = self.isNodeExist(data,"Relation")
            if not asDest and not asSrc:
                q = """ match (source:endpoints), (destination:endpoints) WHERE source.ip="%s" AND destination.ip="%s" MERGE (source)-[r:%s {sourcePort:"%s",destinationPort:"%s"}]-(destination) return type(r) """ \
                % (data["source"],data["destination"],data["type"],data["sourcePort"],data["destinationPort"])
                tx.run(q)
        
        def addLayer3Relation(tx):
            q = """ match (source:endpoints), (destination:endpoints) WHERE source.ip="%s" AND destination.ip="%s" MERGE (source)-[r:%s]-(destination) return type(r) """ \
            % (data["source"],data["destination"],data["type"])
            tx.run(q)
        
        def addLayer2Relation(tx):
            q = """ match (source:endpoints), (destination:endpoints) WHERE source.mac="%s" AND destination.mac="%s" MERGE (source)-[r:%s]-(destination) return type(r) """ \
            % (data["source"],data["destination"],data["type"])
            tx.run(q)

        def updateRelation(tx):
            q = """ match (source:endpoints {ip:"%s"})-[r:%s]->(destination:endpoints {ip:"%s"}) MERGE (source)-[r2:%s]->(destination) SET r2 = r WITH r DELETE r""" \
            % (data["source"],data["type"],data["destination"],data["newType"])
            tx.run(q)
        
        if action == "AddServer":
            self.executeWriteQuery(addServerNode)

        elif action == "AddUDPRelation":
            self.executeWriteQuery(addOneSidedRelation)
        
        elif action == "AddTCPRelation":
            self.executeWriteQuery(addTwoSidedRelation)
        
        elif action == "AddICMPRelation":
            self.executeWriteQuery(addLayer3Relation)

        elif action == "AddARPRelation":
            self.executeWriteQuery(addLayer2Relation)
        
        elif action == "UpdateTCPRelation":
            self.executeWriteQuery(updateRelation)
        
        elif action == "UpdateUDPRelation":
            self.executeWriteQuery(updateRelation)
