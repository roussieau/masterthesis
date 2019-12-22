#!/bin/env python3
import sys, os
directory = sys.argv[1]
files = os.listdir(directory)
for nameOfFile in files:
    newNameOfFile = nameOfFile.replace('-', '').replace('.zip', '')
    path = '{}/{}'.format(directory, nameOfFile)
    os.system('unzip {} -d {}'.format(path, newNameOfFile))
