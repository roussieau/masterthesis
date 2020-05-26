#!/usr/bin/env python3

import psycopg2
import argparse
import textwrap
import random
from datetime import datetime
from time import time

import pandas as pd

db = psycopg2.connect(
    database="thesis",
    user='thesis',
    password='carpestudentem',
    host="revuedesingenieurs.be",
    port="5432"
)

cursor = db.cursor()

def get_total_number():
	cursor.execute("""
        SELECT count(DISTINCT malware_id) 
        FROM detections 
        WHERE clean;
    """)
	amount = cursor.fetchall()[0][0]
	return amount

def get_number_packed(threshold):
    cursor.execute("""
        WITH 
        	counter AS (SELECT malware_id, count(*) as occ
			FROM detections
			WHERE packer NOT like 'error' AND packer NOT like 'none' AND clean
			GROUP BY malware_id)
		SELECT count(malware_id)
		FROM counter
		WHERE occ >= {};
    """.format(threshold))
    amount = cursor.fetchall()[0][0]
    return amount

def get_number_packed_per_detector(detector_name):
	cursor.execute("""
		SELECT count(malware_id)
		FROM detections, detectors
		WHERE packer NOT like 'error' AND packer NOT like 'none' AND clean
		AND detector_id = id AND name = '{}';
	""".format(detector_name))
	amount = cursor.fetchall()[0][0]
	return amount

def get_top_packers():
	cursor.execute("""
		SELECT distinct packer, count(*) 
		FROM detections 
		WHERE clean 
		GROUP BY packer 
		ORDER BY count(*) DESC;
	""")
	top = cursor.fetchall()[1:6]
	return top

def get_number_detections():
	cursor.execute("""
		SELECT count(*) 
		FROM detections;
	""")
	amount = cursor.fetchall()[0][0]
	return amount


def get_stats(threshold=3):
	total = get_total_number()
	packed = get_number_packed(3)
	percentage = (packed/total)*100
	peid = get_number_packed_per_detector('peid')
	manalyze = get_number_packed_per_detector('manalyze')
	peframe = get_number_packed_per_detector('peframe')
	cisco = get_number_packed_per_detector('cisco')
	die = get_number_packed_per_detector('detect-it-easy')
	top = get_top_packers()
	detections = get_number_detections()
	proportions = []
	for i in range(5):
		proportions.append(round((top[i][1]/detections)*100,2))
	print("""
		{} malware out of {} are packed ({}%) with a threshold of {}/5
		PEiD detected {} malware as packed
		Manalyze detected {} malware as packed
		PEFrame detected {} malware as packed
		Cisco detected {} malware as packed
		DIE detected {} malware as packed
		5 most common packers are : {}
		and represent respectively {}% of the detections
		""".format(packed, total, round(percentage,2), threshold,
					peid, manalyze, peframe, cisco, die,
					top, proportions))


def main():
	get_stats(1)

if __name__ == '__main__':
    main()
    cursor.close()
    db.close()