#!/bin/sh

cd tools/manalyze
echo "Installing Manalyze"
apt-get install libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev build-essential cmake git -y
rm -rf CMakeFiles Makefile CMakeCache.txt cmake_install.cmake external
cmake .
make 

cd .. # Back to bin folder
pwd
cd peframe
echo "Installing peframe"
bash install.sh
