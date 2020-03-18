#!/usr/bin/env python3

import sys
from detectItEasy import DetectItEasy
from peframe import Peframe
from manalyze import Manalyze
from peid import Peid

class Malware:
    def __init__(self, date, path):
        splited_path = path.split("/")
        self.date = date
        self.path = path

    def get_name(self):
        return self.path.split("/")[-1]


def main():
    date = sys.argv[1]
    path = sys.argv[2]
    malware = Malware(date, path)
    die = DetectItEasy(malware)
    peframe = Peframe(malware)
    manalyze = Manalyze(malware)
    peid = Peid(malware)
    print(die)
    print(manalyze)
    print(peframe)
    print(peid)

if __name__ == '__main__':
    main()
