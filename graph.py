from neo4j import *

import os
import sys

#neoServer = "neo4j"
neoServer = "localhost"
url = os.getenv("NEO4J_URI", f"bolt://{neoServer}:7687")
username = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "pass")
neo4j_version = os.getenv("NEO4J_VERSION", "4")
database = os.getenv("NEO4J_DATABASE", "PVT")

driver = GraphDatabase.driver(url, auth=basic_auth(username, password))


#
#
#
#
# Server Node -> Relationship {Port1,Port2,Number of packets}
#
# 
#
# 


def addServerNode(ip,mac):
    def addEndpoint(tx):
        q = """ CREATE (endpoint:endpoints {ip:"%s",mac:"%s"}) """ % (ip,mac)
        tx.run(q)

    executeWriteQuery(addEndpoint)

def init():
    def query(tx):
        q = "CREATE (endpoints)"
        tx.run(q)

    executeWriteQuery(query)

def executeWriteQuery(func):
    with driver.session() as session:
        session.write_transaction(func)

    driver.close()


def executeReadQuery(func, obj):
    with driver.session() as session:
        res = session.read_transaction(func, obj)

    driver.close()

    return res
