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

def updatePacker(old, new):
    cursor.execute("""
            UPDATE detections
            SET packer = %s
            WHERE packer = %s
        """, (new, old))
    db.commit()


def getChanges():
    cursor.execute("""
        SELECT old, new
        FROM changes
        ORDER BY old
    """)
    return cursor.fetchall()


changes = getChanges()

for (old, new) in changes:
    print("Rename {} -> {}".format(old, new))
    updatePacker(old, new)
