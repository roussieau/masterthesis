#!/bin/bash



# Detectors
echo "Detectors"
python3 csv_dump_v2.py -l 16000 -d cisco manalyze peid peframe
python3 csv_dump_v2.py -l 16000 -d manalyze peid peframe detect-it-easy
python3 csv_dump_v2.py -l 16000 -d cisco peid peframe detect-it-easy
python3 csv_dump_v2.py -l 16000 -d cisco manalyze peframe detect-it-easy
python3 csv_dump_v2.py -l 16000 -d cisco manalyze peid detect-it-easy

# Others
echo "Others"
python3 csv_dump_v2.py -l 16000 --agreement
