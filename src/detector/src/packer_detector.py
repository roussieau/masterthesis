from database import Database

db = Database()

class PackerDetector:
    def __init__(self, malware):
        self.malware = malware

    def analyze(self):
        pass

    def get_detector_name(self):
        pass

    def get_id(self):
        return db.get_detector_id(detector_name=self.get_detector_name())

    def compute_and_save(self, show=False):
        results = self.analyze()
        if show:
            print("{}: {}".format(self.get_detector_name(), results))

        if type(results) is list:
            for result in results: 
                db.add_analysis(self.malware.get_id(), self.get_id(), result)
        else: 
            db.add_analysis(self.malware.get_id(), self.get_id(), results)

    def __str__(self):
        result = self.analyze()
        return "{}: {}".format(self.get_detector_name(), result)
