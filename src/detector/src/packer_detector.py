from database import Database

db = Database

class PackerDetector:
    def __init__(self, malware):
        self.malware = malware

    def analyze(self):
        pass

    def get_detector_name(self):
        pass

    def get_id(self):
        return db.get_detector_id(self.get_detector_name())

    def __str__(self):
        result = self.analyze()
        result = None if result == [] else result
        return "{}: {}".format(self.get_detector_name(), result)
