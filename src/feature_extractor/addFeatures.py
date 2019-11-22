#!/usr/local/bin/python3
import sys
import os
import subprocess
from Database import *

PATH = '/Users/jeremyminet/Documents/UCL/Memoire/masterthesis/src/feature_extractor/src/pefeats.cpp'

def main():
	db = Database()

	with open(PATH,'r') as features:
		for line in features:
			if "Feature" in line :
				div = line.split(": ")
				num = div[0].split(" ")[1]
				desc = div[1].replace('\n','')
				if "49 - 112" in line :
					for i in range(49,113):
						#print(str(i) + ' - ' + desc)
						db.getFeature(i,desc)
				else :
					db.getFeature(int(num),desc)
					#print(num + ' - ' + desc)

if __name__ == '__main__':
    main()