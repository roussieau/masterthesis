#!/usr/bin/env python3
import sys
import json
import psycopg2
from progress.bar import Bar
USERNAME = 'thesis'
PASSWORD = 'carpestudentem'

f = sys.argv[1]

class Database: 
    def __init__(self):
        self.db = psycopg2.connect(
            database="thesis",
            user=USERNAME,
            password=PASSWORD,
            host="revuedesingenieurs.be",
            port="5432"
        )
        self.cursor = self.db.cursor()

    def getMalware(self, date, malwareHash):
        """Return the malware id"""
        self.cursor.execute("""
            SELECT count(*)
            FROM malwares M
            WHERE M.date = %s AND M.hash = %s;""",
            (date, malwareHash))
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("""
                INSERT INTO malwares (date, hash)
                VALUES (%s, %s)""",
                (str(date), malwareHash))
            self.db.commit()
        self.cursor.execute("""
            SELECT M.id
            FROM malwares M
            WHERE M.date = %s AND M.hash = %s""",
            (date, malwareHash))
        return self.cursor.fetchone()[0]

    def getDetector(self, detector):
        self.cursor.execute("""
            SELECT count(*)
            FROM detectors D
            WHERE D.name = %s""",
            (detector,))
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("""
                INSERT INTO detectors (name)
                VALUES (%s)""",
                (detector,))
            self.db.commit()
        self.cursor.execute("""
            SELECT D.id
            FROM detectors D
            WHERE D.name = %s;""",
            (detector,)) 
        return self.cursor.fetchone()[0]

    def getMalwareDate(self, malwareHash):
        self.cursor.execute("""
            SELECT date
            FROM malwares
            WHERE hash = %s""", (malwareHash,))
        results = self.cursor.fetchall()
        return None if len(results) != 1 else results[0][0]

    def addAnalysis(self, malwareHash, packer):
        date = self.getMalwareDate(malwareHash)
        if date is None:
            return
        m_id = self.getMalware(date, malwareHash)
        d_id = self.getDetector('cisco')
        self.cursor.execute("""
            SELECT count(*)
            FROM detections D
            WHERE D.malware_id = %s AND D.detector_id = %s""",
            (m_id, d_id))
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("""
                INSERT INTO detections (malware_id, detector_id, packer)
                VALUES (%s,%s,%s)""",
                (m_id, d_id, packer))
            self.db.commit()

def main():
    db = Database()
    with open(f) as json_file:
        data = json.load(json_file)
        bar = Bar('Processing', max=len(data))
        for value in data:
            malwareHash = value
            packer = data[value]
            db.addAnalysis(malwareHash, packer)
            bar.next()
        bar.finish()

if __name__ == '__main__':
    main()

