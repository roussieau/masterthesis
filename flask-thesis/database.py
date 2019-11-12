import psycopg2

class Database:
    def __init__(self): 
        try:
            self.conn = psycopg2.connect(dbname="thesis", user="thesis",
                password="carpestudentem", host="revuedesingenieurs.be")
            self.cur = self.conn.cursor()
        except psycopg2.Error as e:
            print('Unable to connect!\n{0}').format(e)
            sys.exit(1)

    def getDetectors(self):
        self.cur.execute("SELECT D.name, count(De.detector_id) as cnt FROM detections De, \
            detectors D WHERE D.id = De.detector_id GROUP BY D.name ")
        return self.cur.fetchall()

    def getPackers(self):
        self.cur.execute("SELECT DISTINCT packer FROM detections")
        return self.cur.fetchall()
