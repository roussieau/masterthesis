import yara
import peutils
import hashlib
import csv
import traceback, sys
from sklearn.externals import joblib
from os.path import isfile, isdir, join, abspath
from numpy import array
from subprocess import check_output
from time import time


class MLChecker:
    need_mapped_pe = False
    name = 'ML classifier'
    pefeats_path = './pefeats'

    def __init__(self, ml_file):
        """
        Initialize a ML checker.
        :param ml_file: the rules file to initiate the checker with. It must be able to be loaded by joblib
        """
        self.isValid = True
        try:
            self.classifier = joblib.load(ml_file)
            self.isValid = hasattr(self.classifier, 'predict_proba')
            if not hasattr(self.classifier, '_categories'):
                feats = []
                for cat in ['entropy', 'ep64', 'header', 'imp_func', 'other', 'section']:
                    if cat in ml_file:
                        feats.append(cat)
                if feats:
                    self.classifier._categories = feats
                    print "Adding", feats, " to features..."

            # print 'Class of classifier:', self.classifier.__class__.__name__
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print '-' * 50
            print 'WARNING: Exception while loading', ml_file
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stdout)
            # print e.__class__, e.message
            self.isValid = False

        self.file = ml_file
        # if self.isValid and hasattr(self.classifier, '_categories'):
        #     print self.classifier._categories

    def classify_single_file(self, input_path):
        extraction_cmd = ""
        if hasattr(self.classifier, '_categories'):
            extraction_cmd = abspath(self.pefeats_path) + " " + abspath(input_path) + " -cat " + " ".join(
                self.classifier._categories)
        else:
            extraction_cmd = abspath(self.pefeats_path) + " " + abspath(input_path)
        start_extr_time = time()
        out_string = check_output(extraction_cmd, shell=True)
        total_extr_time = time() - start_extr_time
        # print 'Executed extraction command ', extraction_cmd, 'in', str(total_extr_time), 'seconds'
        # print 'Output string:', out_string
        if "Invalid" in out_string:
            print input_path, "is not a valid PE file"
        else:
            # print out_string
            feat_list = out_string.replace("\n", "").split(",")[1:]
            # print 'Feats:', feat_list
            feat_list = map(float, feat_list)
            feat_array = array(feat_list).reshape(1, -1)
            prediction = (self.classifier.predict_proba(feat_array)[0]).tolist()
            classes = self.classifier.classes_.tolist()
            classes_probabilities = zip(prediction, classes)

            return classes_probabilities

    def check(self, file):
        """
        Return the response of the classifier on the given pe binary file
        :param file: the file to check.
        :return: the list of matches found
        """

        return [self.classify_single_file(file)]


class YaraChecker:
    need_mapped_pe = False
    name = 'YARA signature'

    def __init__(self, rule_file):
        """
        Initialize a yara checker.
        :param rule_file: the rules file to initiate the checker with.
        """
        self.isValid = True
        try:
            self.rules = yara.compile(rule_file)
        except yara.Error as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print '-' * 50
            print 'WARNING: Exception while loading', rule_file
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stdout)
            self.isValid = False
        self.file = rule_file

    def check(self, file):
        """
        Check whether the file matches at least one rule.
        :param file: the file to check.
        :return: the list of matches found
        """
        matches = None
        try:
            matches = self.rules.match(file)
        except yara.Error:
            return ['yara_error']
        if matches is None:
            return []
        return [m.rule for m in matches]


class PeidChecker:
    need_mapped_pe = True
    name = 'PeID signature'

    def __init__(self, signature_file):
        """
        Initialize a peid checker.
        :param signature_file: the signature file to use.
        """
        self.isValid = True
        try:
            self.signatures = peutils.SignatureDatabase(signature_file)
            self.isValid = (self.signatures.max_depth > 0)

        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print '-' * 50
            print 'WARNING: Exception while loading', signature_file
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stdout)
            self.isValid = False

        self.file = signature_file

    def check(self, file):
        """
        Checks whether the file matches at least one signature.
        :param file: the file to check.
        :return: the list of matches found
        """
        matches = self.signatures.match_all(file, ep_only=True)
        if matches is None:
            return []
        flat_matches = []
        for m in matches:
            flat_matches.extend(m)
        return flat_matches


class HashChecker:
    need_mapped_pe = False
    name = 'HashList'

    def __init__(self, hash_file):
        """
        Initialize a hash list checker.
        :param hash_file: the signature file to use.
        """
        self.isValid = True
        try:
            self.hashes = self.extract_hashes(hash_file)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print '-' * 50
            print 'WARNING: Exception while loading', hash_file
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stdout)
            # self.isValid = False
        self.isValid = hasattr(self, 'hashes')
        self.file = hash_file

    def extract_hashes(self, hash_file):
        with open(hash_file, mode='r') as infile:
            reader = csv.reader(infile)
            hashdict = {rows[0]: rows[1] for rows in reader}
            return hashdict

    def check(self, file):
        """
        Checks whether the file matches a hash.
        :param file: the file to check.
        :return: the list of matches found (will have at most 1 element)
        """
        fileContent = open(file).read()
        hash = hashlib.sha256(fileContent).hexdigest()
        if hash in self.hashes:
            matches = self.hashes[hash]
            # print 'hash of', file, 'is', hash, 'and matches to', matches
            if matches == 'None':
                return []
            else:
                return [matches]
        else:
            # print 'hash of', file, 'is', hash, 'and does not match to anything'
            return []
