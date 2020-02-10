import os
import argparse
from malware import Malware
from database import Database
from progress.bar import Bar


def builder(initPath):
    dates = os.listdir(initPath)
    bar = Bar('Processing', max=len(dates))
    for date in dates:
        bar.next()
        files = os.listdir("{}/{}".format(initPath, date))
        for f in files:
            malware = Malware(date, f, initPath)
            analyse(malware)
    bar.finish()


def analyse(malware):
    if detectors.peid:
        showResult(malware.peidAnalysis(), 'peid', malware)

    if detectors.die:
        showResult(malware.dieAnalysis(), 'die', malware)

    if detectors.manalyze:
        showResult(malware.manalyzeAnalysis(), 'manalyze', malware)

    if detectors.peframe:
        showResult(malware.peframeAnalysis(), 'peframe', malware)


def showResult(result, nameOfDetector, malware):
    if not detectors.quiet:
        print('{} - {} - {}'.format(malware.name, nameOfDetector, result))
    if detectors.save:
        db = Database()
        db.addAnalysis(malware.date, malware.name, nameOfDetector, result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Packer detector')
    parser.add_argument('--peid', dest='peid', action='store_true')
    parser.add_argument('--die', dest='die', action='store_true')
    parser.add_argument('--manalyze', dest='manalyze', action='store_true')
    parser.add_argument('--peframe', dest='peframe', action='store_true')
    parser.add_argument('--save', dest='save', action='store_true')
    parser.add_argument('--quiet', dest='quiet', action='store_true')
    parser.add_argument('path', action='store')

    detectors = parser.parse_args()

    builder(detectors.path)
