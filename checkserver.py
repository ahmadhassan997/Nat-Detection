# sudo python3.5 checkserver.py natdetectionscript.tbx 61.248.134.113

import sys
from scapy.all import *
import subprocess
import time 

# Handle the file arguments
if(len(sys.argv) != 3):
    print('USAGE:  sudo server checkserver.py [SCRIPT_FILE] [DEST_IP]')
    exit(0)
dest = sys.argv[2]
detectionScript = sys.argv[1]

# Make TCP Probe with SYN flag
ip = IP(dst = dest)
syn = TCP(sport = 2000 , dport = 21 , flags = 'S' , seq = 100 , options = [("MSS",1450) , ("NOP",1) , ("Timestamp",(int(time.time()),0)) , ("WScale",5)])
packetToSend = ip/syn
synAck = sr1(packetToSend,timeout=4) # send and receive packet

# Handle the syn response
# 'F': 'FIN',
# 'S': 'SYN',
# 'R': 'RST',
# 'P': 'PSH',
# 'A': 'ACK',
# 'U': 'URG',
# 'E': 'ECE',
# 'C': 'CWR',
if(synAck == None):
    print("The IP address does not exist.")
    exit(0)
if(synAck.sprintf('%TCP.flags%') == 'RA'):
    print("FTP port is not open.")
    exit(0)
else:
    print("SYN ACK Flag Received. Responding with an ACK!!")

# Make the ACK probe to reply to SYN,ACK
tcpOptions = dict(synAck['TCP'].options)
ack = TCP(sport = 2000 , dport = 21 , flags = 'A' , seq = 101 , ack = synAck.seq + 1 , options = [("MSS",1450) , ("NOP",1) , ("Timestamp",(int(time.time()),tcpOptions['Timestamp'][0])) , ("WScale",5)])
ackToSend = ip/ack
response = sr1(ackToSend,timeout=4)

# Invoke the tracebox script
if(response != None or msg.sprintf('%TCP.flags%') != 'RA' or msg.sprintf('%TCP.flags%') != 'SA'):
    print("FTP server found, starting TraceBox.....")
    subprocess.run(["sudo" , "/home/ah/Desktop/projects/measurements/tracebox/src/tracebox/tracebox" , "-s" , detectionScript , "-f" , dest , dest])
else:
    print("FTP Server not found but the port is open, staring TraceBox... ")
    subprocess.run(["sudo" , "/home/ah/Desktop/projects/measurements/tracebox/src/tracebox/tracebox" , "-s" , detectionScript , "-f" , dest , dest])
