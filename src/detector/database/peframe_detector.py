#!/usr/local/bin/python3
import sys
import pefile
import os
import subprocess

def main():
        if len(sys.argv) != 2:
                print('Error : You need to pass the directory of malwares as argument')
                exit()

        packer = "NULL"

        dates = os.listdir(sys.argv[1])
        for date in dates:
                if os.path.isdir(os.path.join(sys.argv[1],date)):
                        folder_path = "{}/{}".format(sys.argv[1], date)
                        files = os.listdir(folder_path)
                        validDate = date.replace("-","")
                        for malware in files:
                                try:
                                        exe_path = "{}/{}".format(folder_path, malware)
                                        output = str(subprocess.check_output("peframe "+exe_path, shell=True))
                                        info_list = output.split("--------------------------------------------------------------------------------")
                                        for i,s in enumerate(info_list):
                                                if "Packer" in s:
                                                        packer = info_list[i+1].split('\\n')[1]
                                                        print(packer)
                                                        break
                                except pefile.PEFormatError:
                                        print("not a valid PE file")
                                except subprocess.CalledProcessError:
                                        print("not a valid PE file")

if __name__ == '__main__':
    main()
