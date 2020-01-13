#!/usr/bin/python3
import sys
from datetime import datetime
sys.path.append('../web')
from database import Database

db = Database()
malware_date = sys.argv[1]
threshold = sys.argv[2]
gt = db.getGroundTruth(malware_date, threshold)
now = datetime.now()
timestamp = now.strftime("%Y.%m.%d-%H.%M")
gt.to_csv('../dumps/'+timestamp+'.csv',index=False)