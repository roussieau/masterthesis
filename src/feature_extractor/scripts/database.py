#!/usr/local/bin/python3 
import psycopg2
from datetime import datetime
from config import USERNAME, PASSWORD

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
        self.cursor.execute("SELECT count(*) FROM malwares M WHERE \
        M.date = '{}' AND M.hash = '{}';".format(date, malwareHash)) 
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("INSERT INTO malwares (date, hash) \
                VALUES ('{}', '{}');".format(str(date), malwareHash))
            self.db.commit()
        self.cursor.execute("SELECT M.id FROM malwares M WHERE \
        M.date = '{}' AND M.hash = '{}';".format(date, malwareHash))
        return self.cursor.fetchone()[0]

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
    def close(self):
        self.cursor.close()
        self.db.close()
