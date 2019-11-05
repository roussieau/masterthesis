import peutils
import pefile

def peidAnalysis(malware):
    with open('db_signatures.txt', encoding="ISO-8859-1",) as f: 
        sig_data = f.read()
        signatures = peutils.SignatureDatabase(data=sig_data)
        malwarePath = "{}/{}".format(malware.path, malware.name)

    try:
        pe = pefile.PE(malwarePath)
        matches = signatures.match(pe, ep_only = True)
        return matches
    except Exception as e:
        print("Bad file: {}".format(malwarePath))
        print(str(e))



