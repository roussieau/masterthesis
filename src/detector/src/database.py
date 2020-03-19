#!/usr/local/bin/python3 
import psycopg2
from datetime import datetime
import os

class Database: 
    def __init__(self):
        self.db = psycopg2.connect(
            database = "thesis", 
            user = os.environ.get("USER"), 
            password = os.environ.get("PASSWORD"), 
            host = "revuedesingenieurs.be", 
            port = "5432"
        )
        self.cursor = self.db.cursor()

    def get_all(self, query, params):
        cursor = self.db.cursor()
        cursor.execute(query, params)
        results = cursor.fetchall()
        cursor.close()
        return results

    def get_one(self, query, params):
        cursor = self.db.cursor()
        cursor.execute(query, params)
        results = cursor.fetchone()[0] if cursor.fetchone() != None else None
        cursor.close()
        return results

    def insert(self, query, params):
        cursor = self.db.cursor()
        cursor.execute(query, params)
        self.db.commit()
        cursor.close()
        

    def get_malware_id(self, date, malware_hash):
        """Return the malware id"""
        malware_id = self.get_one("""
            SELECT M.id 
            FROM malwares M 
            WHERE M.date = %s AND M.hash = %s;
        """, (date, malware_hash))
        if malware_id != None:
            return malware_id
        else: 
            self.insert("""
                INSERT INTO malwares (date, hash)
                VALUES ('{}', '{}');
            """, (str(date), malwareHash))
            return self.get_malware_id(date, malware_hash)

    def get_detector_id(self, detector_name):
        detector_id = self.get_one("""
            SELECT count(*)
            FROM detectors D
            WHERE D.name = %s;
        """, (detector_name,)) 
        if detector_id != None:
            return detector_id
        else: 
            self.insert("""
                INSERT INTO detectors (name)
                VALUES (%s);
            """, (detector,))
        return self.get_detector_id(detector_name)

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

    def addFeature(self, number, desc):
        self.cursor.execute("SELECT count(*) FROM features F WHERE \
        F.num = '{}' AND F.description = '{}';".format(number, desc)) 
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("INSERT INTO features (num, description) \
                VALUES ('{}', '{}');".format(str(number), desc))
            self.db.commit()

    def getFeature(self, featureNum):        
        self.cursor.execute("SELECT F.id FROM features F WHERE \
        F.num = '{}';".format(featureNum)) 
        return self.cursor.fetchone()[0]

    def addFeatureValue(self, date, malwareHash, featureNum, value):
        m_id = self.getMalware(date, malwareHash)
        f_id = self.getFeature(featureNum)
        self.cursor.execute("SELECT count(*) FROM feature_values V WHERE \
        V.malware_id = '{}' AND V.feature_id = '{}' AND V.value = '{}';".format(m_id, f_id, value)) 
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("INSERT INTO feature_values (malware_id, feature_id, value) \
                    VALUES (%s,%s,%s);",(m_id, f_id, value))
            self.db.commit()


    def clear(self):
        self.cursor.execute("DELETE FROM detections WHERE malware_id!=0")
        self.cursor.execute("DELETE FROM malwares WHERE id!=0")
        self.cursor.execute("DELETE FROM detectors WHERE id!=0")
        self.db.commit()

    def close(self):
        self.cursor.close()
        self.db.close()

if __name__ == "__main__":
    db = Database()
