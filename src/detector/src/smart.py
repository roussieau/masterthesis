#!/usr/bin/env python3

import subprocess
from database import Database
import sys

THRESHOLD_MALWARE = 900
THRESHOLD_FEATURE = THRESHOLD_MALWARE * 119

#db = Database()

def convert_date(zipped_date):
    year, month, day = zipped_date.split(".")[0].split("-")
    return "{}{}{}".format(year, month, day)

def is_zip(f):
    splited = f.split('.')
    return len(splited) == 2 and splited[1] == "zip"

def gen_list(list_of_files):
    for f in list_of_files:
        if is_zip(f):
            yield (convert_date(f), f)

def need_to_scan(date):
    return db.get_number_of_detections(date) < THRESHOLD_MALWARE or \
        db.get_number_of_feature_values(date) < THRESHOLD_FEATURE

def scan(date, f):
    zipped_path = "/malwares/{}".format(f)
    new_folder = "/malwares/{}".format(date)
    subprocess.run(["scp", "-i", "/shad", "stud@shadow1.info.ucl.ac.be:~/malware/{}".format(f), zipped_path])
    subprocess.run(["unzip", zipped_path, "-d", new_folder, "-q"])
    subprocess.run(["rm", "-r", zipped_path]) 
    subprocess.run(["./detector.py", "/malwares", "--save", "--auto"])
    subprocess.run(["rm", "-r", new_folder]) 
    

def main():
    starting_date = 0 if len(sys.argv) == 1 else sys.argv[1]
    try:
        list_of_files = subprocess.check_output(["ssh", "stud@shadow1.info.ucl.ac.be", "-i", "/shad",
            "ls", "malware"]).decode("utf-8").split("\n")
    except:
        print("Error to connect in ssh")

    folders = list(gen_list(list_of_files))
    for (date, f) in folders:
        if date > starting_date and need_to_scan(date):
            scan(date, f)

if __name__ == '__main__':
    main()
