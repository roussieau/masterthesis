FROM ubuntu:latest

WORKDIR src

COPY . .

RUN apt-get -y update
RUN apt-get install -y dialog apt-utils git

# Installation python
RUN apt-get install -y python3 python3-pip
RUN pip3 install pefile

# Installation of Manalyze
RUN apt-get install -y libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev build-essential cmake git vim nano wget

WORKDIR manalyze/Manalyze
RUN cmake .
RUN make

# Installation peframe
WORKDIR /src/peframe
RUN bash install.sh
RUN pip3 install -r requirements.txt
RUN python3 setup.py install

WORKDIR /src
