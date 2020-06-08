FROM ubuntu:latest

RUN mkdir /malwares

WORKDIR detector 

ADD tools /detector/tools
ADD src /detector/src
ADD app /detector/app
ADD install.sh install.sh
RUN apt-get -y update
RUN apt-get install -y dialog apt-utils git libpq-dev cmake build-essential vim unzip

# Install python
RUN apt-get install -y python3 python3-pip
RUN pip3 install pefile psycopg2 progress flask flask_restful joblib sklearn pandas

WORKDIR /detector/tools/pepac
RUN git clone https://github.com/avast-tl/pelib.git
WORKDIR pelib/build
RUN cmake ..
RUN make

WORKDIR /detector/tools/pefeats/build
RUN cmake ..
RUN make

WORKDIR /detector
RUN bash install.sh
WORKDIR /detector/src
