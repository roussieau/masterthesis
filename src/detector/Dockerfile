FROM ubuntu:latest

WORKDIR src

COPY . .

RUN apt-get update
RUN apt-get install -y dialog apt-utils

# Installation python
RUN apt-get install -y python3 python3-pip
RUN pip3 install pefile

# Installation of Manalyze
RUN apt-get install -y libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev build-essential cmake git vim nano wget

WORKDIR manalyze/Manalyze
RUN cmake .
RUN make
WORKDIR /src

#Install Nauz
RUN apt-get install -y qtcreator qt5-default
RUN mkdir /nauz
WORKDIR /nauz
RUN git clone https://github.com/horsicq/Nauz-File-Detector.git
WORKDIR /nauz/Nauz-File-Detector/
RUN chmod 777 build_lin64.sh
# RUN ./build_lin64.sh
WORKDIR /src

