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

    def getChanges(self):
        self.cur.execute("SELECT * FROM changes")
        return self.cur.fetchall()

    def addChange(self, old, new):
        self.cur.execute("SELECT * FROM changes WHERE old = %s AND new = %s", \
            (old, new))
        if len(self.cur.fetchall()) == 0:
            self.cur.execute("INSERT INTO changes (old, new) VALUES (%s, %s)", \
                (old, new))
            self.conn.commit()

    def updatePacker(self, old, new):
        try:
            self.cur.execute("UPDATE detections SET packer = %s WHERE packer LIKE %s", (new, old))
        except psycopg2.Error as e:
            print('Error to update').format(e)
        print("updated "+old+" to "+new)
        self.conn.commit()
