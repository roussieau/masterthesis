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

    dates = os.listdir(sys.argv[1])
    db = Database()
    for date in dates:
        if os.path.isdir(os.path.join(sys.argv[1],date)):
            folder_path = "{}/{}".format(sys.argv[1], date)
            files = os.listdir(folder_path)
            validDate = date.replace("-","")
            for malware in files:
                exe_path = "{}/{}".format(folder_path, malware)
                output = str(subprocess.check_output(NAUZ+" "+exe_path, shell=True))
                if "Packer" in output :
                	packer = sanitize(output.split(":")[-1])
                else :
                	packer = "NULL"
                db.addAnalysis(validDate, malware, "nauz", packer)

def sanitize(entry):
	return entry.replace('\\n\'','').replace('\\n','')

if __name__ == '__main__':
    main()
