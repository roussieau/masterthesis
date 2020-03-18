#!/usr/bin/env python3 

import psycopg2
import argparse
from datetime import datetime

import pandas as pd

def query_feature_values(only_bool, limit):
    """ Query feature values to remote database"""
    # if boolean features only
    cond = ""
    limit = " LIMIT {}".format(limit) if limit != None else ""
    if only_bool:
        for f_id in get_boolean_id():
            cond += " {},".format(f_id[0])
        
        #build the condition, [:-1] is there to pick up the last ","
        cond = "AND F.num IN (" + cond[:-1] + ") "

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
    print("There is some troubles with {} malwares " \
        .format(len(malwares_error)))

    return final_array

def get_labels():
    """ Returns the following tuple (malware_id, isPacked)"""
    cursor.execute("""
        WITH packed AS (
          SELECT t1.date, t1.malware_id, t1.packer, t1.agree, t2.total
          FROM (SELECT M.date, D.malware_id, D.packer, count(packer) AS agree
                    FROM detections D, malwares M
                    WHERE M.id = D.malware_id
                    GROUP BY M.date, D.malware_id, D.packer) AS t1
          JOIN(SELECT malware_id, count(DISTINCT detector_id) AS total
                   FROM detections B
                   GROUP BY malware_id
                   HAVING count(DISTINCT detector_id) = 5
          ) AS t2
          ON t1.malware_id = t2.malware_id)
        SELECT malware_id, 1 AS value
        FROM packed A
        WHERE NOT EXISTS(
            SELECT * 
            FROM packed B 
            WHERE A.malware_id = B.malware_id  AND B.packer like 'none')
        UNION 
        SELECT malware_id, 1 AS value
        FROM packed 
        WHERE packer LIKE 'none' AND total - agree >= 3
        UNION 
        SELECT malware_id, 0 AS value
        FROM packed 
        WHERE packer LIKE 'none' AND total - agree < 3
        ORDER BY malware_id
        """)
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--bool_only", help="Return only boolean features",
        action="store_true", default=False)
    parser.add_argument("--limit", type=int, help="Limit number of malawares")
    args = parser.parse_args()

    result_of_db = query_feature_values(args.bool_only, args.limit)
    name_of_features = get_feature_labels(result_of_db)
    print("Number of features: {}".format(len(name_of_features)))
    features = get_feature_values(result_of_db, len(name_of_features))
    labels = get_labels()
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
