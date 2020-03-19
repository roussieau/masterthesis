FROM ubuntu:latest

WORKDIR detector 

ADD tools /detector/tools
ADD src /detector/src
ADD install.sh install.sh
RUN apt-get -y update
RUN apt-get install -y dialog apt-utils git libpq-dev

# Installation python
RUN apt-get install -y python3 python3-pip
RUN pip3 install pefile psycopg2 progress

RUN bash install.sh
