#!/usr/bin/env python3

import sys
import os
import argparse 
from detectItEasy import DetectItEasy
from peframe import Peframe
from manalyze import Manalyze
from peid import Peid
from pefeats import Pefeats
from database import Database
import os

db = Database()

class Malware:
    def __init__(self, date, path):
        print("date: {}, path: {}".format(date, path))
        self.date = date
        self.path = path

    def get_name(self):
        return self.path.split("/")[-1]

    def get_id(self):
        return db.get_malware_id(self.date, self.get_name())

    def print_all(self):
        print(DetectItEasy(self))
        print(Peframe(self))
        print(Manalyze(self))
        print(Peid(self))
        print(Pefeats(self))


    def analyze(self, show=False):
        DetectItEasy(self).compute_and_save(show)
        Peframe(self).compute_and_save(show)
        Manalyze(self).compute_and_save(show)
        Peid(self).compute_and_save(show)

def builder(path):
    dates = os.listdir(path)
    for date in dates:
        files = os.listdir("{}/{}".format(path, date)) 
        for f in files:
            yield (date, "{}/{}/{}".format(path, date, f))

def main():
    parser = argparse.ArgumentParser(description='Packer detector')
    parser.add_argument('path', action='store', help='Path to the malware')
    parser.add_argument('--date', action='store', help='Date with the following\
        structure YYYYMMDD')
    parser.add_argument('--print', action='store_true', help="Only show result")
    parser.add_argument('--verbose', action='store_true', default=False,
        help='Save to db')

    args = parser.parse_args()

    malwares = builder(args.path) if args.date is None else [(args.date, args.path)]
    for (date, path) in malwares:
        malware = Malware(date, path) #.analyze(args.verbose)
        if args.print:
            malware.print_all()


if __name__ == '__main__':
    main()
