import helper
from fire import Fire
from flask import Flask, request, render_template
from flask_socketio import SocketIO, emit
from uuid import uuid4
import sys
import os
import json

app = Flask(__name__, template_folder="templates")
app.secret_key = str(uuid4())
socketio = SocketIO(app)

# Dirs
DB_FOLDER = "jsons/"
PCAP_FOLDER = "pcaps/"

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
    pcap = request.files.get("pcap")
    fullPath = helper.saveFile(pcap)
    helper.parse(fullPath)
    with open(DB) as db:
        newProtocols = json.load(db)
    return render_template('index.html',protocols=newProtocols)


def showHelpMenu():
    description = """usage: python3 PVT.py [--help] [OPTIONS]
    
    PVT is a tool for creating a network map from PCAP

    optional arguments:
    --pcap      PCAP path for visualization [Default: False].
    """
    print(description)


def startPVT(help=False, debug=False, web=False, dev=False,port=5000):
    if help:
        showHelpMenu()
        sys.exit(0)

    if dev:
        for pcap in os.listdir("Test"):
            helper.parse(f"Test/{pcap}")

    if web:
        if debug:
            socketio.run(app,debug=True, host='0.0.0.0', port=port)
        else:
            app.run(debug=False, host='0.0.0.0', port=port)



if __name__ == '__main__':
    os.makedirs(DB_FOLDER, exist_ok=True)
    os.makedirs(PCAP_FOLDER, exist_ok=True)
    Fire(startPVT) 
