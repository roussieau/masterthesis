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
    SELECT M.date, count(M.date)
    FROM malwares M
    WHERE M.id IN (
        SELECT D.malware_id
        FROM detections D
        GROUP BY D.malware_id
        HAVING count(malware_id) = 5)
    GROUP BY M.date
    ORDER BY M.date
"""
cursor.execute(query)
results = cursor.fetchall()
total = 0
for (date, number) in results:
    total += number
    print("{} => {}".format(date, number))

print("Total = {}".format(total))

cursor.close()
db.close()

