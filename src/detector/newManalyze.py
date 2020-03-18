import subprocess
import json

class Manalyze:
    def __init__(self, malware):
        self.malware = malware

    def analyze(self):
        try:
            output = subprocess.check_output(["./tools/manalyze/bin/manalyze",
            "--plugins=peid", "-o", "json", self.malware.path])
            data = json.loads(output)
            return getPacker(data)
        except:
            return 'error' 
 

def getPacker(data):
    firstKey = list(data.keys())[0]

    plugins = data[firstKey]["Plugins"]
    if len(plugins) > 0:
       return plugins["peid"]["plugin_output"]["info_0"]
    return None
