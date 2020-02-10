import subprocess
import json

def dieAnalysis(malware):
    malwarePath = "{}/{}".format(malware.path, malware.name)
    try:
        output = subprocess.check_output(["./die/die/diec.sh", "-showjson:yes", \
        "-singlelineoutput:no", malwarePath])
        data = json.loads(output.decode("utf-8"))
        return getPacker(data)
    except:
        return 'error' 

def getPacker(data):
    for value in data["detects"]:
        if value["type"] == "packer":
            return value["name"]
    return None
