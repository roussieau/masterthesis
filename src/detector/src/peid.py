import peutils
import pefile

class Peid:
    def __init__(self, malware):
        self.malware = malware

    def analyze(self):
        with open('./../tools/peid/db_signatures.txt', encoding="ISO-8859-1",) as f: 
            try:
                sig_data = f.read()
                signatures = peutils.SignatureDatabase(data=sig_data)

                pe = pefile.PE(self.malware.path)
                matches = signatures.match(pe, ep_only = True)
                return matches
            except Exception as e:
                print(e)
                return 'error'
