import unittest

from csv_dump_v2 import *

class TestCsvDump(unittest.TestCase):

    def test_build_cond(self):
        cond = build_cond('features', ['f1', 'f2', 'f3'])
        self.assertEqual(cond, "AND features IN ( f1, f2, f3) ")
        cond_zero = build_cond('features', None)
        self.assertEqual(cond_zero, "")

    def test_query_feature_values(self):
        pass
        #print(query_feature_values(1))

    def test_get_labels(self):
        malwares = [
            (1, 0, 2, 3, 'upx', 5),
            (2, 1, 2, 2, 'upx', 5),
            (3, 0, 3, 2, 'upx', 5),
            (5, 0, 4, 2, 'upx', 5),
            (5, 0, 2, 3, 'upx', 5),
        ]
        print(get_labels(3, data = malwares))

if __name__ == '__main__':
    unittest.main()
