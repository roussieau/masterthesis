#!/usr/bin/env python3
import psycopg2

db = psycopg2.connect(
        database="thesis",
        user='thesis',
        password='carpestudentem',
        host="revuedesingenieurs.be",
        port="5432"
        )

cursor = db.cursor()

query = """
    SELECT hash
    FROM malwares
    WHERE id NOT IN (
        SELECT malware_id
        FROM detections
        WHERE detector_id = 19);
"""
cursor.execute(query)
results = cursor.fetchall()
with open("out.txt", "w") as f:
    for (m_hash, ) in results:
        f.write(m_hash + '\n')

cursor.close()
db.close()

