#!/bin/bash
ROOTDIR=/pepac/mount

YARARULES=""
PEIDRULES=""
HASHLISTS=""
CLASSIFIERS=""

DOCKERCOMMAND=""

if groups $USER  | grep &>/dev/null '\bdocker\b'
  then
    DOCKERCOMMAND="docker"
  else
    DOCKERCOMMAND="sudo docker"
fi

rm -f test_files.txt
touch test_files.txt

for filename in tests/*; do
	echo "$ROOTDIR/$filename" >> test_files.txt
done

for filename in ./yara_rules/*; do
	name=$(basename $filename)
    YARARULES="$YARARULES -y $ROOTDIR/yara_rules/$name"
done

for filename in ./peid_rules/*; do
	name=$(basename $filename)
    PEIDRULES="$PEIDRULES -p $ROOTDIR/peid_rules/$name"
done

for filename in ./hash_lists/*; do
	name=$(basename $filename)
    HASHLISTS="$HASHLISTS -l $ROOTDIR/hash_lists/$name"
done

for filename in ./ml_classifiers/*; do
	name=$(basename $filename)
    CLASSIFIERS="$CLASSIFIERS -c $ROOTDIR/ml_classifiers/$name"
done

$DOCKERCOMMAND run -v `pwd`:$ROOTDIR -t pepac python /pepac/bin/pepac.py\
    $YARARULES $PEIDRULES $HASHLISTS $CLASSIFIERS\
    -o $ROOTDIR/results.json\
    -i $ROOTDIR/test_files.txt

rm -f test_files.txt
