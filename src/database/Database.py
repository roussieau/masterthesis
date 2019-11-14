#!/usr/local/bin/python3 
import psycopg2
from credentials import USERNAME, PASSWORD
from datetime import datetime

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
        self.cursor.execute("SELECT count(*) FROM malwares M WHERE \
        M.date = '{}' AND M.hash = '{}';".format(date, malwareHash)) 
        if self.cursor.fetchone()[0] == 0:
            print("new file")
            self.cursor.execute("INSERT INTO malwares (date, hash) \
                VALUES ('{}', '{}');".format(str(date), malwareHash))
            self.db.commit()
        self.cursor.execute("SELECT M.id FROM malwares M WHERE \
        M.date = '{}' AND M.hash = '{}';".format(date, malwareHash))
        print("deja là")
        return self.cursor.fetchone()[0]

    def getAllMalwares(self):
        self.cursor.execute("SELECT * FROM malwares M ")
        return self.cursor.fetchall()

    def getDetector(self, detector):
        self.cursor.execute("SELECT count(*) FROM detectors D WHERE \
        D.name = '{}';".format(detector)) 
        if self.cursor.fetchone()[0] == 0:
            print("new detector")
            self.cursor.execute("INSERT INTO detectors (name) \
                VALUES ('{}');".format(detector))
            self.db.commit()
        self.cursor.execute("SELECT D.id FROM detectors D WHERE \
        D.name = '{}';".format(detector)) 
        return self.cursor.fetchone()[0]

    def getAllDetectors(self):
        self.cursor.execute("SELECT * FROM detectors D ")
        return self.cursor.fetchall()

    def addAnalysis(self, date, malwareHash, detector, packer):
        m_id = self.getMalware(date, malwareHash)
        d_id = self.getDetector(detector)
        self.cursor.execute("SELECT count(*) FROM detections D WHERE \
        D.malware_id = '{}' AND D.detector_id = '{}';".format(m_id, d_id)) 
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("INSERT INTO detections (malware_id, detector_id, packer) \
                    VALUES (%s,%s,%s);",(m_id, d_id, packer))
            self.db.commit()

    def getAllAnalysis(self):
        self.cursor.execute("SELECT * FROM detections D ")
        return self.cursor.fetchall()

    def clear(self):
        self.cursor.execute("DELETE FROM detections WHERE malware_id!=0")
        self.cursor.execute("DELETE FROM malwares WHERE id!=0")
        self.cursor.execute("DELETE FROM detectors WHERE id!=0")
        self.db.commit()

    def close(self):
        self.cursor.close()
        self.db.close()

    def main(self):

        h = open("Nauzresult.txt","r")
        lines = h.readlines()
        for x in lines :
            tab = x.split(" - ")
            db.addAnalysis(20190615, tab[0], "Nauz", tab[2])

if __name__ == "__main__":
    db = Database()
    db.main()
