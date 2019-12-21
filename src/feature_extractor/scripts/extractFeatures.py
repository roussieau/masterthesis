#!/usr/bin/python3
import subprocess
import sys
import os
from database import Database
from progress.bar import Bar

db = Database()

def analyze(malwarePath, date, malware):
    output = subprocess.check_output(['/pepac/bin/pefeats', malwarePath])
    cleanOuput = output.decode('utf8')
    features = cleanOuput.split(',')

    for i in range(1, len(features)):
        db.addFeatureValue(date, malware, i, features[i])

def buildPath():
    startPath = sys.argv[1]
    dates = os.listdir(startPath)
    bar = Bar('Processing', max=len(dates))
    for date in dates:
        bar.next()
        datePath = '{}/{}'.format(startPath, date)
        malwares = os.listdir(datePath)
        for malware in malwares:
            malwarePath = '{}/{}'.format(datePath, malware)
            analyze(malwarePath, date, malware)
    bar.finish()

if __name__ == '__main__':
    buildPath()
