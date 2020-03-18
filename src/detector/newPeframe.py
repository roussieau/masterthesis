import peutils
import pefile
import subprocess
import json

class Peframe:
    def __init__(self, malware):
        self.malware = malware

    def analyze(self):
        try:
            out = subprocess.check_output(['peframe', '-sj',
            self.malware.path], universal_newlines=True)
            data = json.loads(out)
            return  data["peinfo"]["features"]["packer"]
        except:
            return ['error']
