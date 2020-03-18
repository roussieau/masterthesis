import subprocess
import json

class DetectItEasy:
    
    def __init__(self, malware):
        self.malware = malware

    def analyze(self):
        try:
            output = subprocess.check_output(["./../tools/detect-it-easy/diec.sh",
                "-showjson:yes", "-singlelineoutput:no", self.malware.path])
            data = json.loads(output.decode("utf-8"))
            return getPacker(data)
        except:
            return 'error' 


def getPacker(data):
    for value in data["detects"]:
        if value["type"] == "packer":
            return value["name"]
    return None
