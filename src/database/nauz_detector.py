#!/usr/local/bin/python3
import sys
import os
import subprocess
from Database import *

NAUZ = "/Users/jeremyminet/Documents/UCL/Memoire/Nauz-File-Detector/build/release/nfdc"

def main():
    if len(sys.argv) != 2:
        print('Error : You need to pass the directory of malwares as argument')
        exit()

    malwares = os.listdir(sys.argv[1])
    date = sys.argv[1].split("/")[-2]
    db = Database()

    for malware in malwares:
        exe_path = sys.argv[1] + malware
        output = str(subprocess.check_output(NAUZ+" "+exe_path, shell=True))
        if "Packer" in output :
        	packer = sanitize(output.split(":")[-1])
        else :
        	packer = "NULL"
        db.addAnalysis(date, malware, "nauz", packer)

def sanitize(entry):
	return entry.replace('\\n\'','').replace('\\n','')

if __name__ == '__main__':
    main()
