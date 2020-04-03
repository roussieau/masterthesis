#!/usr/bin/env python3
import psycopg2

db = psycopg2.connect(
        database="thesis",
        user='thesis',
        password='carpestudentem',
        host="revuedesingenieurs.be",
        port="5432"
        )
cursor = db.cursor()


def update_packer(old, new):
    cursor.execute("""
            UPDATE detections
            SET packer = %s,
                clean = True
            WHERE packer = %s
        """, (new, old))
    db.commit()


def get_changes():
    cursor.execute("""
        SELECT old, new
        FROM changes
        ORDER BY old
    """)
    return cursor.fetchall()


def remove_empty_packers():
    cursor.execute("""
        UPDATE detections
        SET packer = 'none',
            clean = True
        WHERE packer is NULL
    """)
    db.commit()


if __name__ == '__main__':
    changes = get_changes()

    for (old, new) in changes:
        print("Rename {} -> {}".format(old, new))
        update_packer(old, new)

    print("Convert empty detections to none")
    remove_empty_packers()
