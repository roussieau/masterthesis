from database import Database
import subprocess

db = Database()

class Pefeats:
    def __init__(self, malware):
        self.malware = malware

    def analyze(self):
        try:
            output = subprocess.check_output(["/detector/tools/pefeats/build/pefeats",
            self.malware.path])
            return output.decode('utf-8').split(',')[1:]
        except:
            return []


    def compute(self, save=False, show=False):
        results = self.analyze()
        for i in range(len(results)):
            feature_num = i + 1
            if not save or show:
                print("Feature n {} => {}".format(feature_num, results[i]))
            if save:
                db.add_feature_value(self.malware.get_id(),
                    feature_num, results[i])
            

    def __str__(self):
        return "Malware hash: {} \n Features values:\n {}".format(
            self.malware.get_name(), self.analyze())
