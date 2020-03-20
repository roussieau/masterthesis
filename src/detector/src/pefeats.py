from database import Database
import subprocess

class Pefeats:
    def __init__(self, malware):
        self.malware = malware

    def analyze(self):
        output = subprocess.check_output(["./../tools/pefeats/build/pefeats",
            self.malware.path])
        return output.decode('utf-8').split(',')[1:]

    def __str__(self):
        return "Malware hash: {} \n Features values:\n {}".format(
            self.malware.get_name(), self.analyze())
