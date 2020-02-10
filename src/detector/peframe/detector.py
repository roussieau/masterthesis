import peutils
import pefile
import subprocess
import json

def peframeAnalysis(malware):
    try:
        malwarePath = "{}/{}".format(malware.path, malware.name)
        out = subprocess.check_output(['peframe', '-sj', malwarePath], universal_newlines=True)
        data = json.loads(out)
        return data["peinfo"]["features"]["packer"]
    except:
        return ['error']
