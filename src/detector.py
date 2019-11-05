import os
import sys
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
    print("Peid      | {}".format(malware.peidAnalysis()))
    print("Die       | {}".format(malware.dieAnalysis()))
    print("Manalyze  | {}".format(malware.manalyzeAnalysis()))
    


if __name__ == "__main__":
    builder(sys.argv[1])
