import helper
from fire import Fire
from flask import Flask, request, render_template
from uuid import uuid4
import sys

app = Flask(__name__, template_folder="templates")
app.secret_key = str(uuid4())  # Nice


@app.route('/', methods=['GET'])
def graph():
    return render_template('index.html')



def showHelpMenu():
    description = """usage: python3 PVT.py [--help] [OPTIONS]
    
    PVT is a tool for creating a network map from PCAP

    optional arguments:
    --pcap      PCAP path for visualization [Default: False].
    """
    print(description)


def startPVT(pcap="Test/t.pcapng", help=False, debug=False, prod=False,port=5000):
    if help:
        showHelpMenu()
        sys.exit(0)

    if pcap:
        helper.parse(pcap)

    if prod:
        if debug:
            app.run(debug=True, host='0.0.0.0', port=port)
        else:
            app.run(debug=False, host='0.0.0.0', port=port)



if __name__ == '__main__':
    Fire(startPVT) 
    app.start()