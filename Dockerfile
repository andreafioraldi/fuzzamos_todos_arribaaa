FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y git build-essential sudo

RUN mkdir -p /workdir/fuzzamos

WORKDIR /workdir/fuzzamos
COPY . /workdir/fuzzamos

RUN ./qsym/setup_docker.sh
RUN cd qsym && pip install .
RUN ln -s /workdir/fuzzamos/afl-fuzz /bin/
RUN ln -s /workdir/fuzzamos/run_qsym_afl /bin/
RUN ln -s /workdir/fuzzamos/generators/* /bin/

ENV AFL_PATH=/workdir/fuzzamos/afl/
