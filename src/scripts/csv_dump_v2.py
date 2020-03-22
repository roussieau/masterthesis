#!/usr/bin/env python3 

import psycopg2
import argparse
import textwrap
import sys
from datetime import datetime

import pandas as pd

def query_feature_values(mode, limit, selection=None):
    """ Query feature values to remote database"""
   
    cond = ""
    multiplicator = 119

     # if boolean features only
    if mode == 1:
        multiplicator = 0
        for f_id in get_boolean_id():
            multiplicator += 1
            cond += " {},".format(f_id[0])
        
        #build the condition, [:-1] is there to pick up the last ","
        cond = "AND F.num IN (" + cond[:-1] + ") "
    elif mode == 2:
        multiplicator = len(selection)
        for f in selection:
            cond += " {},".format(f)

        #build the condition, [:-1] is there to pick up the last ","
        cond = "AND F.num IN (" + cond[:-1] + ") "

    # number of total features should be limit * wanted features (mode 0 is 119, mode 1 
    # is number of boolean features and mode 2 is length of selection array) """
    limit = " LIMIT {}".format(limit*multiplicator) if limit != None else ""
    print("Request feature values")
    cursor.execute("""
        SELECT FV.malware_id, F.num, FV.value
        FROM features F, feature_values FV
        WHERE FV.feature_id = F.id 
        {}
        ORDER BY FV.malware_id, F.num
        {};
    """.format(cond, limit))
    features = cursor.fetchall()
    return features

def get_boolean_id():
    """ Returns the num of the boolean values"""
    print("Request boolean values")
    cursor.execute("""
        SELECT DISTINCT F.num 
        FROM features F, feature_values FV 
        WHERE FV.feature_id NOT IN 
            (SELECT DISTINCT A.feature_id 
             FROM feature_values A
             WHERE A.value != 0
                AND A.value != 1)
            AND FV.feature_id = F.id
        ORDER BY F.num;
    """)
    boolean_id = cursor.fetchall()
    print("The num of boolean values are : {}".format(boolean_id))
    return boolean_id

def get_feature_labels(array):
    """ Returns the different features for the first malware"""
    first_malware = array[0][0]
    feature_labels = []
    for row in array:
        malware_id = row[0]
        feature_number = row[1]
        if malware_id != first_malware:
            return feature_labels
        feature_labels.append(feature_number)

def get_feature_values(array, number_of_features):
    """Returns a 2D array with the following structure :
       [[malware_1, feature_1, feature_2, feature3, ...],
        ...
        [malware_14, feature1, feature_2, feature_3, ...]]"""
    current_id = -1
    tmp_features = []
    malwares_error = []
    final_array = []

    for row in array:
        malware_id = row[0]
        feature_value = row[2]

        if current_id != malware_id:

            if len(tmp_features) == number_of_features + 1: 
                final_array.append(tmp_features)
            else:
                malwares_error.append(malware_id)

            tmp_features = []
            tmp_features.append(malware_id)
            current_id = malware_id

        tmp_features.append(feature_value)



    print("Number of malwares: {}".format(len(final_array)))
    print("There is some trouble with {} malware(s) " \
        .format(len(malwares_error)))

    return final_array


def get_labels(threshold,selection=None, errors_as_packed=False):
    """ Returns the following tuple (malware_id, isPacked)"""
    if threshold > 5:
        print( "Error :Threshold bigger than number of detectors", sys.stderr)
        sys.exit()
    selection_size = 5
    desired_detectors = ""
    error_extent = ""
    table = "detections"
    none_and_error = ""
    binary_labels = """
        SELECT malware_id, 1 AS value
        FROM packed 
        WHERE packer LIKE 'none' AND total - agree >= {}
        UNION 
        SELECT malware_id, 0 AS value
        FROM packed 
        WHERE packer LIKE 'none' AND total - agree < {}
        ORDER BY malware_id;
        """.format(threshold,threshold)
    if selection != None:
        if threshold > len(selection):
            print( "Error :Threshold bigger than number of detectors", sys.stderr)
            sys.exit()
        cond = ""
        for f in selection:
                cond += " '{}',".format(f)
        cond = "(" + cond[:-1] + ") "
        selection_size = len(selection)
        request = "SELECT id FROM detectors WHERE name IN {}".format(cond)
        desired_detectors = """
            desired_detectors AS ({}),
            reduced_detections AS (
                SELECT D.malware_id, D.detector_id, D.packer 
                FROM detections D, desired_detectors P 
                WHERE D.detector_id = P.id ORDER BY D.malware_id
            ),""".format(request)
        table = "reduced_detections"
    if not errors_as_packed:
        error_extent = "OR B.packer LIKE 'error'";
        none_and_error = """,
            none_and_error AS (
            SELECT malware_id, sum(agree) AS the_sum
            FROM packed
            WHERE packer LIKE 'error' or packer LIKE 'none'
            GROUP BY malware_id)
            """
        binary_labels = """
            SELECT malware_id, 0 AS value
            FROM none_and_error
            WHERE the_sum >= {} - {}
            UNION
            SELECT malware_id, 1 AS value
            FROM none_and_error
            WHERE the_sum < {} - {}
            ORDER BY malware_id;
            """.format(selection_size, threshold, selection_size, threshold)

    cursor.execute("""
        WITH {}
        packed AS (
            SELECT t1.date, t1.malware_id, t1.packer, t1.agree, t2.total
            FROM (SELECT M.date, D.malware_id, D.packer, count(packer) AS agree
                    FROM {} D, malwares M
                    WHERE M.id = D.malware_id
                    GROUP BY M.date, D.malware_id, D.packer) AS t1
            JOIN(SELECT malware_id, count(DISTINCT detector_id) AS total
                   FROM {} B
                   GROUP BY malware_id
                   HAVING count(DISTINCT detector_id) = {}
            ) AS t2
            ON t1.malware_id = t2.malware_id){}
        SELECT malware_id, 1 AS value
        FROM packed A
        WHERE NOT EXISTS(
            SELECT * 
            FROM packed B 
            WHERE A.malware_id = B.malware_id  AND (B.packer LIKE 'none' {}))
        UNION 
        {}
        """.format(desired_detectors,table,table,selection_size,none_and_error,error_extent,binary_labels))
    return cursor.fetchall()


def merge_fv_and_label(feature_values, labels):
    """Merge feature values with corresponding label"""
    fv_index = 0
    label_index = 0 
    global_array = []

    while(fv_index < len(feature_values) and label_index < len(labels)):
        # Corresponding malware id
        if feature_values[fv_index][0] == labels[label_index][0]:
            new_row = feature_values[fv_index][1:] + [labels[label_index][1]]
            global_array.append(new_row)
            fv_index += 1
            label_index += 1
        elif feature_values[fv_index][0] < labels[label_index][0]:
            fv_index += 1
        else:
            label_index += 1

    print("{:.2%} of feature values in the final" \
        .format(len(global_array)/len(feature_values)))
    print("{:.2%} of labels in the final" \
        .format(len(global_array)/len(labels)))

    return global_array

def create_csv(array, labels):
    now = datetime.now()
    timestamp = now.strftime("%Y.%m.%d-%H.%M")
    df = pd.DataFrame(data=array,
                      index=[ i for i in range(len(array)) ],
                      columns=[ 'f'+str(i) for i in labels ] + ['label'])
    df.to_csv('../dumps/'+timestamp+'.csv', index=False)
    print("File {}.csv created".format(timestamp))

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-t",
                        "--threshold",
                        type=int,
                        help="Threshold for ground truth generation (max. 5)",
                        default=3)
    parser.add_argument("-l",
                        "--limit", 
                        type=int, 
                        help="Limit number of malwares")
    parser.add_argument("-m",
                        "--mode",
                        type=int,
                        help=textwrap.dedent('''\
                                0 (default): all features
                                1: only boolean features
                                2: features from parameter array
                                 '''),
                        default=0)
    parser.add_argument("-a",
                        "--arr",
                        nargs="+", 
                        help="Array of wanted features e.g. 46 87 101 119")
    parser.add_argument("-d",
                        "--detector",
                        nargs="+",
                        help=textwrap.dedent('''\
                            Array of wanted detectors with values 
                            in [peframe, peid, manalyze, cisco, detect-it-easy]
                            '''))
    parser.add_argument("-e",
                        "--error",
                        type=bool,
                        help="Consider detection errors as a packed label",
                        default=False)

    args = parser.parse_args()
    if args.mode == 2 and args.arr is None:
        parser.error("mode 2 requires array of features, -h for help")

    result_of_db = query_feature_values(args.mode, args.limit, args.arr)
    name_of_features = get_feature_labels(result_of_db)
    print("Number of features: {}".format(len(name_of_features)))
    features = get_feature_values(result_of_db, len(name_of_features))
    labels = get_labels(args.threshold,args.detector,args.error)
    final_array = merge_fv_and_label(features, labels)
    create_csv(final_array, name_of_features)

db = psycopg2.connect(
    database="thesis",
    user='thesis',
    password='carpestudentem',
    host="revuedesingenieurs.be",
    port="5432"
)

cursor = db.cursor()

if __name__ == '__main__':
    main()

cursor.close()
