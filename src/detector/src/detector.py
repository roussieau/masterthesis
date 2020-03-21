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
        self.date = date
        self.path = path

    def get_name(self):
        return self.path.split("/")[-1]

    def get_id(self):
        return db.get_malware_id(self.date, self.get_name())

    def get_feature_values(self):
        return Pefeats(self).compute()

    def have_detections(self):
        return db.have_detections(self.get_id())

    def have_feature_values(self):
        return db.have_detections(self.get_id())

    def print_all(self):
        print(DetectItEasy(self))
        print(Peframe(self))
        print(Manalyze(self))
        print(Peid(self))
        print(Pefeats(self))

    def compute(self, save=False, show=False):
        DetectItEasy(self).compute(save, show)
        Peframe(self).compute(save, show)
        Manalyze(self).compute(save, show)
        Peid(self).compute(save, show)

    def auto(self, save=False, show=False):
        if not self.have_detections():
            self.compute(save=save, show=show)
        if not self.have_feature_values():
            print(self.get_feature_values())

def builder(path):
    dates = os.listdir(path)
    for date in dates:
        files = os.listdir("{}/{}".format(path, date)) 
        for f in files:
            yield (date, "{}/{}/{}".format(path, date, f))

def main():
    parser = argparse.ArgumentParser(description='Packer detector')
    parser.add_argument('path',
                        action='store',
                        help='Path to the malware')

    parser.add_argument('--date',
                        action='store',
                        help='Date with the following structure YYYYMMDD')

    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help="Only show result")

    parser.add_argument('--auto',
                        default=False,
                        action='store_true',
                        help="Auto scan")

    parser.add_argument('--save',
                        action='store_true',
                        default=False,
                        help='Save to db')

    args = parser.parse_args()

    malwares = builder(args.path) if args.date is None else [(args.date, args.path)]
    for (date, path) in malwares:
        malware = Malware(date, path)
        if args.auto:
            malware.auto(save=args.save, show=args.verbose)


if __name__ == '__main__':
    main()
