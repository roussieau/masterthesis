import peutils
import pefile
from packer_detector import PackerDetector

class Peid(PackerDetector):

    def get_detector_name(self):
        return "peid"

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
