FROM debian:sid
RUN apt-get update && apt-get install -y build-essential vim cmake git python-yara python-pip && apt-get clean -y
RUN pip install -U pip
RUN pip install pefile sklearn numpy scipy psycopg2-binary

RUN mkdir /pepac

WORKDIR /pepac
RUN git clone https://github.com/avast-tl/pelib.git
WORKDIR /pepac/pelib/
RUN mkdir build
WORKDIR /pepac/pelib/build
RUN cmake ..
RUN make

ADD ./src /pepac/src
WORKDIR /pepac/src
RUN mkdir /pepac/build
WORKDIR /pepac/build
RUN cmake ../src
RUN make
RUN mkdir /pepac/bin
WORKDIR /pepac/bin
RUN cp ../build/pefeats .
RUN cp ../src/ComposedClassifier.py .
RUN cp ../src/pepac.py .
RUN cp ../src/checkers.py .
RUN ls
