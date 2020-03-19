import peutils
import pefile
import subprocess
import json
from packer_detector import PackerDetector

class Peframe(PackerDetector):

    def get_detector_name(self):
        return "peframe"

    def analyze(self):
        try:
            out = subprocess.check_output(['peframe', '-sj',
            self.malware.path], universal_newlines=True)
            data = json.loads(out)
            results = data["peinfo"]["features"]["packer"] 
            return results if len(results) != 0 else None
        except:
            return ['error']
