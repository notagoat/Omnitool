#Omnitool 0.5
#------------
# Tools included
#   - Fuzzer
#   - Port Scanner
#   - Connection Strength Detector

import socket
import fileinput
import re
import subprocess
import sys
import NetworkManager

import requests

from datetime import datetime

subprocess.call('clear', shell=True)

def main():
    print("""
       ____  __  __ _   _ _____ _______ ____   ____  _
      / __ \|  \/  | \ | |_   _|__   __/ __ \ / __ \| |
     | |  | | \  / |  \| | | |    | | | |  | | |  | | |
     | |  | | |\/| | . ` | | |    | | | |  | | |  | | |
     | |__| | |  | | |\  |_| |_   | | | |__| | |__| | |____
      \____/|_|  |_|_| \_|_____|  |_|  \____/ \____/|______|  """)
    print('\n')
    print('"I\'m Commander Shepherd and this is my favourite hacking tool on the Citadel"')
    options()

def options():
    print()
    print("1:    Port Scanner")
    print("2:    Fuzzer")
#    print("3:    Traffic Sniffer")
    print("3:    Conection Strength Detector")
    print()
    choice = input("Select a tool: ")
    if choice == "1":
        portScanner()
    elif choice == "2":
        fuzzer()
#    elif choice == "3":
#        traffic()
    elif choice == "3":
        strength()
    else:
        print("Invalid Choice")
        options()

#def traffic():
#    print("Frick")

def fuzzer():
    try:
        urlRanCount = 0
        headers = {'user-agent': 'my-app/0.0.1'}
        fuzzTarget = input("Enter a Website for fuzzing scan: ")
        target = requests.get(fuzzTarget, headers=headers)
        if target.status_code == 200:
            print("~" * 60)
            print("Target is up commencing fuzzing")
            print("~" * 60)
        else:
            print("Target is giving status code %s" %target.status_code)
            fuzzer()

        try:
            timeStart = datetime.now()
            with open('fuzzingUrlList.txt') as inputFile:
                for i, line in enumerate(inputFile):
                    urlRanCount += 1
                    rt = requests.get(fuzzTarget + line,headers=headers,allow_redirects=False)
                    if rt.status_code not in [404,400,302]:
                        print(fuzzTarget + line +" : "+ str(rt.status_code))

            timeEnd = datetime.now()
            timeTotal = str(timeEnd - timeStart)
            print("~" * 60)
            print("Scan Complete: " + timeTotal)
            print("Have A Nice Day!")

        except KeyboardInterrupt:
            print("Scan Cancelled.")
            sys.exit()

    except requests.exceptions.MissingSchema:
        print("Invalid URL. Try adding http://?")



def portScanner():
    remoteServer = input("Enter a host to scan: ")
    remoteServerIP = socket.gethostbyname(remoteServer)

    portLength = input("How many ports to scan from 1: ")
    print("~" * 60)
    print("Scanning %s ports on host: %s" %(portLength,remoteServerIP))
    print("~" * 60)
    portLength = int(portLength)
    timeStart = datetime.now()

    try:
        for port in range(1,portLength):
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP,port))
            if result == 0:
                print("Port %i:    Open" %(port))
            sock.close()
        print("~" * 60)


    except KeyboardInterrupt:
        print("Scan Cancelled.")
        sys.exit()

    except socket.gaierror:
        print("Hostname failed to resolve.")
        sys.exit()

    except socket.error:
        print("Failed to connect to server.")
        sys.exit()

    timeEnd = datetime.now()

    timeTotal = str(timeEnd - timeStart)
    print("Scan Complete: " + timeTotal)
    print("Have A Nice Day!")

def strength():
    for dev in NetworkManager.NetworkManager.GetDevices():
        if dev.DeviceType != NetworkManager.NM_DEVICE_TYPE_WIFI:
            continue
        aps = [ap for ap in dev.SpecificDevice().GetAccessPoints()]
        for ap in sorted(aps, key=lambda ap: ap.Ssid):
            print(u"%s: %s" % (ap.Ssid, ap.Strength))


if __name__ == "__main__":
    main()
