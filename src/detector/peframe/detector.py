import peutils
import pefile

def peframeAnalysis(malware):
    out = subprocess.check_output(['peframe', '-sj', 'a006230ff4533597c7e6c343794f3b78'], universal_newlines=True)
    data = json.loads(out)
    return data["peinfo"]["features"]["packer"]
