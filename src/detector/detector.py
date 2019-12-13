import os
import sys
import argparse
from malware import Malware

def builder(initPath):
    dates = os.listdir(initPath)
    for date in dates:
        files = os.listdir("{}/{}".format(initPath, date))
        for f in files:
           malware = Malware(date, f, initPath) 
           analyse(malware)


def analyse(malware):
    print("=================================")
    print(malware.name)
    if detectors.peid: 
        print("Peid      | {}".format(malware.peidAnalysis()))

    if detectors.die: 
        print("Die       | {}".format(malware.dieAnalysis()))

    if detectors.manalyze: 
        print("Manalyze  | {}".format(malware.manalyzeAnalysis()))

    if detectors.peframe: 
        print("Peframe   | {}".format(malware.manalyzeAnalysis()))
   


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Packer detector')
    parser.add_argument('--peid', dest='peid', action='store_true') 
    parser.add_argument('--die', dest='die', action='store_true')
    parser.add_argument('--manalyze', dest='manalyze', action='store_true')
    parser.add_argument('--peframe', dest='peframe', action='store_true')
    parser.add_argument('path', action='store')

    detectors = parser.parse_args()

    builder(detectors.path)
