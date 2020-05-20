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

    def test_get_label_threshold(self):
        malwares = [
            # id, error, none, other, packer, max_packer)
            (  1,    0,    2,     3,  'upx',          2),
        ]
        label = get_labels(3, data=malwares)[0][1]
        self.assertEqual(label, 1)
        label = get_labels(4, data=malwares)[0][1]
        self.assertEqual(label, 0)
        malwares = [
            # id, error, none, other, packer, max_packer)
            (  1,    1,    3,     1,  'upx',          2),
        ]
        label = get_labels(3, data=malwares)[0][1]
        self.assertEqual(label, 0)


    def test_get_label_agreement(self):
        malwares = [
            # id, error, none, other, packer, max_packer)
            (  1,    0,    2,     3,  'upx',          2),
        ]
        label = get_labels(3, data=malwares, agreement=True)[0][1]
        self.assertEqual(label, 0)
        malwares = [
            # id, error, none, other, packer, max_packer)
            (  1,    0,    2,     3,  'upx',          3),
        ]
        label = get_labels(3, data=malwares, agreement=True)[0][1]
        self.assertEqual(label, 1)
        

if __name__ == '__main__':
    unittest.main()
