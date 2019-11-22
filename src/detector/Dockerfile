FROM ubuntu:latest

WORKDIR src

COPY . .

RUN apt-get -y update
RUN apt-get install -y dialog apt-utils

# Installation python
RUN apt-get install -y python3 python3-pip
RUN pip3 install pefile

# Installation of Manalyze
RUN apt-get install -y libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev build-essential cmake git
WORKDIR manalyze/Manalyze
RUN cmake .
RUN make
WORKDIR /src

