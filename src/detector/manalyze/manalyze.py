import subprocess
import json

def manalyzeAnalysis(malware):
    malwarePath = "{}/{}".format(malware.path, malware.name)
    output = subprocess.check_output(["./manalyze/Manalyze/bin/manalyze", "--plugins=peid", \
        "-o", "json", malwarePath])
    try:
        data = json.loads(output.decode("utf-8"))
        return getPacker(data)
    except:
        return 'error' 

def getPacker(data):
    firstKey = list(data.keys())[0]

    plugins = data[firstKey]["Plugins"]
    if len(plugins) > 0:
       return plugins["peid"]["plugin_output"]["info_0"]
    return None
