#!/usr/local/bin/python3
import pefile
import peutils
import os
import sys

def main():
    if len(sys.argv) != 2:
        print('Error : You need to pass the directory of malwares as argument')
        exit()

    malwares = os.listdir(sys.argv[1])

    with open('db_signatures.txt', encoding="ISO-8859-1",) as f: 
        sig_data = f.read()
        signatures = peutils.SignatureDatabase(data=sig_data)

    for malware in malwares:
        exe_path = sys.argv[1] + malware
        try:
            pe = pefile.PE(exe_path)
            matches = signatures.match(pe, ep_only = True)
            if matches != None and len(matches) > 0:
                print(malware + " - " + matches[0])
        except:
            print("Bad file")

if __name__ == '__main__':
    main()
