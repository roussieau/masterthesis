import psycopg2


def zero_if_null(value):
    return value if value else 0 


db = psycopg2.connect(
    database="thesis",
    user='thesis',
    password='carpestudentem',
    host="revuedesingenieurs.be",
    port="5432"
)

cursor = db.cursor()

cursor.execute("""
SELECT DISTINCT D.malware_id as malware_id,
       E.error,
       N.none,
       O.other,
       M.packer,
       M.max
FROM detections D
FULL JOIN  (
    SELECT malware_id, count(*) as error
    FROM detections
    WHERE packer like 'error' AND clean
    GROUP BY malware_id) E
ON D.malware_id = E.malware_id
FULL JOIN  (
    SELECT malware_id, count(*) as none
    FROM detections
    WHERE packer like 'none' AND clean
    GROUP BY malware_id) N
ON D.malware_id = N.malware_id
FULL JOIN  (
    SELECT malware_id, count(*) as other
    FROM detections
    WHERE packer NOT like 'error' AND packer NOT like 'none' AND clean
    GROUP BY malware_id) O
ON D.malware_id = O.malware_id
FULL JOIN  (
    SELECT malware_id, packer ,count(*) as max
    FROM detections
    WHERE packer NOT like 'error' AND packer NOT like 'none' AND clean
    GROUP BY malware_id, packer) M
    ON D.malware_id = M.malware_id
ORDER BY malware_id;
""")
results = cursor.fetchall()
for (m_id, error, none, other, packer, number) in results:
    error = zero_if_null(error)
    none = zero_if_null(none)
    other = zero_if_null(other)
    number = zero_if_null(number)
    if error + none + other == 5:
        print("{} - {} + {} + {}".format(m_id, error, none, other))

	
