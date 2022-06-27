from re import A
import helper
from fire import Fire
from flask import Flask, request, render_template
from flask_socketio import SocketIO, emit
from uuid import uuid4
import sys
import os
import json
from time import sleep
from threading import Thread

app = Flask(__name__, template_folder="templates")

app.secret_key = str(uuid4())

socketio = SocketIO(app,async_mode='threading')

client = ""
fullPath = ""

# Dirs
DB_FOLDER = "jsons/"
PCAP_FOLDER = "pcaps/"
LOCAL_DEV = "localhost"
LOCAL_PROD = "neo4j"

# Files
DB = "jsons/data.db"


@app.route('/', methods=['GET'])
def graph():
    if not os.path.exists(DB):
        helper.initDB()

    with open(DB) as db:
        newProtocols = json.load(db)

    return render_template('index.html',protocols=newProtocols)


@app.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    global fullPath
    pcap = request.files.get("pcap")
    fullPath = helper.saveFile(pcap)
    with open(DB) as db:
        newProtocols = json.load(db)
    return render_template('index.html',protocols=newProtocols)


@socketio.on('connect')
def connection():
    global client
    client = request.sid
    
    if "upload_pcap" in request.referrer:
        if fullPath:
            socketio.start_background_task(runParse,fullPath=fullPath,client=client,sio=socketio)
            socketio.emit("finish")
    else:
        pass


@socketio.on('updateSid')
def updateSid(sid):
    global client
    client = sid


def sendData(percent, client, sio):
    sio.emit('update', percent, room=client)


def runParse(fullPath,client,sio):
    helper.parse(fullPath,client,sio)


def showHelpMenu():
    description = """usage: python3 PVT.py [--help] [OPTIONS]
    
    PVT is a tool for creating a network map from PCAP

    optional arguments:
    --pcap      PCAP path for visualization [Default: False].
    --debug     Enable debug [Default: False]
    --web       Start Web service [Default: False]
    --dev       Load pcaps from Test directory [Default: False]
    --port      Listening port for web service [Default: 8443]
    """
    print(description)


def startPVT(help=False, debug=False, web=False, dev=False,port=8443):
    if help:
        showHelpMenu()
        sys.exit(0)

    if dev:
        os.environ["graphHost"] = LOCAL_DEV
    else:
        os.environ["graphHost"] = LOCAL_PROD

    if web:
        if debug:
            socketio.run(app,debug=True, host='0.0.0.0', port=port)
        else:
            socketio.run(app,debug=False, host='0.0.0.0', port=port)



if __name__ == '__main__':
    os.makedirs(DB_FOLDER, exist_ok=True)
    os.makedirs(PCAP_FOLDER, exist_ok=True)
    Fire(startPVT) 
