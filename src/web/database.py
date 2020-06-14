#!/usr/local/bin/python3 
import psycopg2
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score

from config import USER, PASSWORD, HOST
from datetime import datetime

class Database: 
    def __init__(self):
        self.db = psycopg2.connect(
            database="thesis",
            user=USER,
            password=PASSWORD,
            host=HOST,
            port="5432"
        )
        self.cursor = self.db.cursor()

    def getMalware(self, date, malwareHash):
        """ return the malware id if it exists
        it is added to the database if it does not exist """
        self.cursor.execute("""
            SELECT count(*)
            FROM malwares M
            WHERE M.date = %s AND M.hash = %s;""", (date, malwareHash))
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("""
                INSERT INTO malwares (date, hash)
                VALUES (%s, %s)""", (date, malwareHash))
            self.db.commit()
        self.cursor.execute("""
            SELECT M.id
            FROM malwares M
            WHERE M.date = %s AND M.hash = %s""", (date, malwareHash))
        return self.cursor.fetchone()[0]

    def getPackers(self):
        self.cursor.execute("""
            SELECT DISTINCT packer
            FROM detections D
            WHERE D.packer NOT IN (
                SELECT old
                FROM changes
                UNION
                SELECT new
                FROM changes
            )
            AND D.clean = False
            ORDER by packer
        """)
        return self.cursor.fetchall()

    def getDates(self, from_date, to_date):
        self.cursor.execute("""
            SELECT DISTINCT date
            FROM malwares
            WHERE date >= %s
            AND date <= %s
            ORDER BY date;
        """,(from_date, to_date))
        result = self.cursor.fetchall()
        return self.sanitize(result)

##### Changes

    def addChange(self, old, new):
        self.cursor.execute("""
            INSERT INTO changes
            VALUES (%s, %s)
        """, (old, new))
        self.db.commit()

    def updatePacker(self, old, new):
        self.cursor.execute("""
            UPDATE detections
            SET packer = %s
            WHERE packer = %s
        """, (new, old))
        self.db.commit()

    def getChanges(self):
        self.cursor.execute("""
            SELECT old, new
            FROM changes
            ORDER BY old
        """)
        return self.cursor.fetchall()

    def getCountByDates(self):
        self.cursor.execute("""
            SELECT M.date, count(M.date)
            FROM malwares M
            GROUP BY M.date
            ORDER BY date""")
        return self.cursor.fetchall()

    def getMalwaresFromDate(self, date):
        self.cursor.execute("""
            SELECT M.hash
            FROM malwares M
            WHERE M.date = %s""", (date,))
        return self.cursor.fetchall()


    def getAllMalwares(self):
        self.cursor.execute("""
            SELECT * FROM malwares M
            """)
        return self.cursor.fetchall()

    def getDetector(self, detector):
        self.cursor.execute("""
            SELECT count(*) 
            FROM detectors D 
            WHERE D.name = %s
            """, (detector,)) 
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("""
                INSERT INTO detectors (name)
                VALUES %s
                """, (detector,))
            self.db.commit()
        self.cursor.execute("""
            SELECT D.id 
            FROM detectors D 
            WHERE D.name = %s
            """,(detector,)) 
        return self.cursor.fetchone()[0]

    def getAllDetectors(self):
        self.cursor.execute("""
            SELECT detectors.name, count(malware_id)
            FROM detections, detectors
            WHERE detector_id = detectors.id
            GROUP BY detectors.name, detector_id
            """)
        return self.cursor.fetchall()

    def addAnalysis(self, date, malwareHash, detector, packer):
        m_id = self.getMalware(date, malwareHash)
        d_id = self.getDetector(detector)
        self.cursor.execute("""
            SELECT count(*) 
            FROM detections D 
            WHERE D.malware_id = %s 
            AND D.detector_id = %s
            """, (m_id, d_id)) 
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("""
                INSERT INTO detections (malware_id, detector_id, packer)
                VALUES (%s,%s,%s)
                """, (m_id, d_id, packer))
            self.db.commit()

    def getAllAnalysis(self):
        self.cursor.execute("""
                SELECT * 
                FROM detections D
                ORDER BY D.packer
            """)
        return self.cursor.fetchall()

    def addFeature(self, number, desc):
        self.cursor.execute("""
            SELECT count(*) 
            FROM features F 
            WHERE F.num = %s 
            AND F.description = %s
            """, (number, desc)) 
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("""
                INSERT INTO features (num, description)
                VALUES (%s, %s)
                """, (number, desc))
            self.db.commit()

    def getFeature(self, featureNum):        
        self.cursor.execute("""
            SELECT F.id 
            FROM features F 
            WHERE F.num = %s
            """, (featureNum,)) 
        return self.cursor.fetchone()[0]

    def addFeatureValue(self, date, malwareHash, featureNum, value):
        m_id = self.getMalware(date, malwareHash)
        f_id = self.getFeature(featureNum)
        self.cursor.execute("""
            SELECT count(*) 
            FROM feature_values V 
            WHERE V.malware_id = %s 
            AND V.feature_id = %s 
            AND V.value = %s
            """, (m_id, f_id, value)) 
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute("""
                INSERT INTO feature_values (malware_id, feature_id, value)
                VALUES (%s,%s,%s)
                """, (m_id, f_id, value))
            self.db.commit()


    def clear(self):
        self.cursor.execute("DELETE FROM detections WHERE malware_id!=0")
        self.cursor.execute("DELETE FROM malwares WHERE id!=0")
        self.cursor.execute("DELETE FROM detectors WHERE id!=0")
        self.db.commit()

    def close(self):
        self.cursor.close()
        self.db.close()

    def getMalwareResult(self, date, name):
        malwareId = self.getMalware(date, name)
        self.cursor.execute("""
            SELECT  A.name, D.packer
            FROM detections D, detectors A 
            WHERE D.malware_id=%s AND D.detector_id = A.id
            """, (malwareId,))
        return self.cursor.fetchall()

    def getFeatureResult(self, date, name):
        malwareId = self.getMalware(date, name)
        self.cursor.execute("""
            SELECT F.description, V.value
            FROM feature_values V, features F
            WHERE malware_id=%s AND V.feature_id = F.id""", (malwareId,))
        return self.cursor.fetchall()

    def findFaultyHashes(self, date):
        self.cursor.execute("""
            SELECT hash 
            FROM malwares 
            WHERE date = %s AND id NOT IN
            (SELECT DISTINCT malware_id AS id 
            FROM feature_values FV, malwares M 
            WHERE M.id=FV.malware_id 
            AND M.date = %s 
            ORDER BY malware_id)
            """,(date,date)) 
        return self.cursor.fetchall()

    # Ground Truth generation

    def getFV(self, date):
        self.cursor.execute("""
            SELECT FV.value 
            FROM feature_values FV, malwares M
            WHERE M.date=%s
            AND M.id = FV.malware_id
            ORDER BY id;
            """,(date,))
        res = self.cursor.fetchall()
        cleaned = self.sanitize(res)
        input_data = [cleaned[i:i + 119] for i in range(0, len(cleaned), 119)]
        return input_data

    def getLabels(self, date, threshold, agreement):
        if agreement:
            self.cursor.execute("""
                WITH scanned AS ( 
                SELECT DISTINCT FV.malware_id AS id FROM feature_values FV, malwares M 
                WHERE FV.malware_id=M.id AND M.date=%s),
                filtered AS (
                (SELECT malware_id, packer, count(packer) AS occ FROM detections 
                WHERE packer != 'none' GROUP BY malware_id, packer HAVING count(packer) >= 1 ORDER BY malware_id) 
                UNION 
                (SELECT malware_id, packer, 0 AS occ FROM detections D, malwares M
                WHERE packer = 'none' AND M.id=D.malware_id AND M.date = %s GROUP BY malware_id, packer HAVING count(packer) = 5 ORDER BY malware_id)),
                maximum AS (
                SELECT malware_id AS id, max(occ) AS top FROM filtered GROUP BY malware_id ORDER BY malware_id),
                counter AS (
                SELECT T.id, T.top AS occ FROM maximum T RIGHT JOIN scanned M ON T.id=M.id),
                labels AS (
                (SELECT id, 1 AS label FROM counter WHERE occ >= %s) UNION
                (SELECT id, 0 AS label FROM counter WHERE occ < %s)
                ORDER BY id)
                SELECT label FROM labels;
                """,(date, date, threshold, threshold))
        else :
            self.cursor.execute("""
                WITH scanned AS (
                SELECT DISTINCT FV.malware_id AS id FROM feature_values FV, malwares M
                WHERE FV.malware_id=M.id AND M.date=%s),
                counter AS (
                SELECT M.id, count(D.packer) AS occ 
                FROM detections D 
                RIGHT JOIN scanned M ON D.malware_id=M.id AND D.packer != 'none'
                GROUP BY M.id),
                labels AS (
                (SELECT id, 1 AS label FROM counter WHERE occ >= %s) UNION
                (SELECT id, 0 AS label FROM counter WHERE occ < %s)
                ORDER BY id)
                SELECT label FROM labels
                """,(date, threshold, threshold))
        output_data = self.cursor.fetchall()
        cleaned = self.sanitize(output_data)
        return cleaned

    def getGroundTruth(self, date, threshold, agreement):
        labels = self.getFV(date)
        data = np.array(labels)
        if(len(data) != 0):
            df1=pd.DataFrame(data=data[0:,0:],
                            index=[i for i in range(data.shape[0])],
                            columns=['f'+str(i) for i in range(data.shape[1])])
            
            target = self.getLabels(date, threshold, agreement)
            df2=pd.DataFrame({'label':target})
            return df1.join(df2)
        else:
            return pd.DataFrame()

    def sanitize(self, res):
        return [res[i][0] for i in range(0, len(res), 1)]

if __name__ == "__main__":
    db = Database()
    print(db.getLabels("20190615",3,1))
