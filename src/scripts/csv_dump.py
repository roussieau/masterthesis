#!/usr/bin/python3
import sys
import pandas as pd
from datetime import datetime
sys.path.append('../web')
from database import Database

db = Database()
from_date = sys.argv[1]
to_date = sys.argv[2]
threshold = sys.argv[3]
agreement = sys.argv[4]
dt_array = []
interval = db.getDates(from_date, to_date)
for x in interval:
	dt_array.append(db.getGroundTruth(x, int(threshold), int(agreement)))
now = datetime.now()
timestamp = now.strftime("%Y.%m.%d-%H.%M")
gt = pd.concat(dt_array)
print("CSV generated contains %d entries." % gt.shape[0])
gt.to_csv('../dumps/'+timestamp+'.csv',index=False)