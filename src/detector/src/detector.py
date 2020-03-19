#!/usr/bin/env python3

import sys
import argparse 
from detectItEasy import DetectItEasy
from peframe import Peframe
from manalyze import Manalyze
from peid import Peid
from database import Database
import os

db = Database()

class Malware:
    def __init__(self, date, path):
        self.date = date
        self.path = path

    def get_name(self):
        return self.path.split("/")[-1]

    def get_id(self):
        return db.get_malware_id(self.date, self.get_name())

    def analyze(self, show=False):
        DetectItEasy(self).compute_and_save(show)
        Peframe(self).compute_and_save(show)
        Manalyze(self).compute_and_save(show)
        Peid(self).compute_and_save(show)


def main():
    parser = argparse.ArgumentParser(description='Packer detector')
    parser.add_argument('date', action='store', help='Date with the following\
     structure YYYYMMDD')
    parser.add_argument('path', action='store', help='Path to the malware')

    args = parser.parse_args()
    malware = Malware(args.date, args.path)
    malware.analyze()

if __name__ == '__main__':
    main()
