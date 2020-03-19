#!/usr/bin/env python3

import sys
from detectItEasy import DetectItEasy
from peframe import Peframe
from manalyze import Manalyze
from peid import Peid
from database import Database
import os

db = Database()

class Malware:
    def __init__(self, date, path):
        splited_path = path.split("/")
        self.date = date
        self.path = path

    def get_name(self):
        return self.path.split("/")[-1]

    def get_id(self):
        return db.get_malware_id(self.date, self.get_name())

    def analyze(self):
        print(DetectItEasy(self))
        print(Peframe(self).get_id())
        print(Manalyze(self))
        print(Peid(self))
   


def main():
    date = sys.argv[1]
    path = sys.argv[2]
    malware = Malware(date, path)
    print("malware id: {}".format(malware.get_id()))
    malware.analyze()

if __name__ == '__main__':
    main()
