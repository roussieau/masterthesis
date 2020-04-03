#!/bin/bash

# Threshold 1
python3 csv_dump_v2.py -t 1 -l 6000
python3 csv_dump_v2.py -t 1 -l 14000
python3 csv_dump_v2.py -t 1 -l 21000
python3 csv_dump_v2.py -t 1 -l 31000
python3 csv_dump_v2.py -t 1 -l 1000 -s 20190808

# Threshold 2
python3 csv_dump_v2.py -t 2 -l 6000
python3 csv_dump_v2.py -t 2 -l 14000
python3 csv_dump_v2.py -t 2 -l 21000
python3 csv_dump_v2.py -t 2 -l 31000
python3 csv_dump_v2.py -t 2 -l 1000 -s 20190808

# Threshold 4
python3 csv_dump_v2.py -t 4 -l 6000
python3 csv_dump_v2.py -t 4 -l 14000
python3 csv_dump_v2.py -t 4 -l 21000
python3 csv_dump_v2.py -t 4 -l 31000
python3 csv_dump_v2.py -t 4 -l 1000 -s 20190808

# Threshold 5
python3 csv_dump_v2.py -t 5 -l 6000
python3 csv_dump_v2.py -t 5 -l 14000
python3 csv_dump_v2.py -t 5 -l 21000
python3 csv_dump_v2.py -t 5 -l 31000
python3 csv_dump_v2.py -t 5 -l 1000 -s 20190808