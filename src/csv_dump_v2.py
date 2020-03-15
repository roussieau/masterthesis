#!/usr/bin/env python3 

import psycopg2

def query_feature_values():
    """ Query feature values to remote database"""
    print("Request feature values")
    cursor.execute("""
        SELECT FV.malware_id, F.num, FV.value
        FROM features F, feature_values FV
        WHERE FV.feature_id = F.id 
        ORDER BY FV.malware_id, F.num;
    """)
    features = cursor.fetchall()
    print("Features loaded")
    return features

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



    print("Number of malwares : {}".format(len(final_array)))
    print("There some troubles with {} malwares " \
        .format(len(malwares_error)))

    return final_array

def get_labels():
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
          ON t1.malware_id = t2.malware_id),
        nofiltred AS (
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
        )
        SELECT N.malware_id, N.value 
        FROM nofiltred N
        WHERE N.malware_id IN (
            SELECT FV.malware_id
            FROM feature_values FV
            GROUP BY FV.malware_id
            HAVING count(FV.malware_id) = 119)
        ORDER BY N.malware_id;
    """)
    return cursor.fetchall()

def fusion_fv_and_label(feature_values, labels):
    fv_index = 0
    label_index = 0 
    global_array = []
    while(fv_index < len(feature_values) and label_index < len(labels)):
        if feature_values[fv_index][0] == labels[label_index][0]:
            new_row = feature_values[fv_index][1:] + [labels[label_index][1]]
            global_array.append(new_row)
            fv_index += 1
            label_index += 1
        elif feature_values[fv_index][0] < labels[label_index][0]:
            fv_index += 1
        else:
            label_index += 1

    return global_array
        
        
    

db = psycopg2.connect(
    database="thesis",
    user='thesis',
    password='carpestudentem',
    host="revuedesingenieurs.be",
    port="5432"
)

cursor = db.cursor()

result_of_db = query_feature_values()
labels = get_feature_labels(result_of_db)
print("Number of features: {}".format(len(labels)))
fv = get_feature_values(result_of_db, len(labels))
lb = get_labels()
fusion_fv_and_label(fv, lb)

cursor.close()
