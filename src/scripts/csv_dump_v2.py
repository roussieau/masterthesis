#!/usr/bin/python3

import psycopg2

def build_array(results):
    first_malware = results[0][0]
    current_malware = first_malware
    num_features = []
    tmp_features = []
    malware_error = []

    final_array = []
    for row_id in range(len(results)):
        if results[row_id][0] != current_malware:
            if len(tmp_features) == len(num_features):
                final_array.append(tmp_features)
            else: 
                malware_error.append(results[row_id][0])

            tmp_features = []
            current_malware = results[row_id][0]

        #Build num_features
        if results[row_id][0] == first_malware:
            num_features.append(results[row_id][1])
            tmp_features.append(results[row_id][2])
        tmp_features.append(results[row_id][2])

    print("Features : {}".format(num_features))
    print("Number of malwares : {}".format(len(final_array)))
    print("There some troubles with the following malware_id : {}" \
        .format(malware_error))
        

db = psycopg2.connect(
    database="thesis",
    user='thesis',
    password='carpestudentem',
    host="revuedesingenieurs.be",
    port="5432"
)

cursor = db.cursor()

# Get feature values
print("Request feature values")
cursor.execute("""
    SELECT FV.malware_id, F.num, FV.value
    FROM features F, feature_values FV
    WHERE FV.feature_id = F.id
    ORDER BY FV.malware_id, F.num;
""")
features = cursor.fetchall()
print("Features loaded")

build_array(features)

cursor.close()
