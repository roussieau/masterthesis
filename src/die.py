import subprocess
import json

def dieAnalysis(malware):
    malwarePath = "{}/{}".format(malware.path, malware.name)
    output = subprocess.check_output(["./die/diec.sh", "-showjson:yes", \
        "-singlelineoutput:no", malwarePath])
    try:
        data = json.loads(output.decode("utf-8"))
        return getPacker(data)
    except:
        print("Error to load json")
        return None

def getPacker(data):
    for value in data["detects"]:
        if value["type"] == "packer":
            return value["name"]
    return None
