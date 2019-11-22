#!/usr/local/bin/python3
import sys
import os
import subprocess
from Database import *

CMD = "/pepac/bin/pefeats "

def main():
	if len(sys.argv) != 2:
		print('Error : You need to pass the directory of malwares as argument')
		exit()

	db = Database()

	dates = os.listdir(sys.argv[1])
	for date in dates:
		if os.path.isdir(os.path.join(sys.argv[1],date)):
			folder_path = "{}/{}".format(sys.argv[1], date)
			files = os.listdir(folder_path)
			validDate = date.replace("-","")
			for malware in files:
				exe_path = "{}/{}".format(folder_path, malware)
				output = subprocess.check_output(CMD+exe_path, shell=True)
				div = output.decode('utf-8').split(",")
				malware_name = div[0]
				for i in range(1,120):
					feature_num = i
					feature_value = div[i]
					print(malware_name + " - " + str(feature_num) + " - " + feature_value)
					db.addFeatureValue(validDate, malware_name, feature_num, feature_value)

if __name__ == '__main__':
    main()
