FROM ubuntu:latest

RUN apt-get update && apt-get install -y build-essential automake1.11 autoconf libevent-dev libseccomp-dev git

ADD . /src
WORKDIR /src

RUN ./autogen.sh
RUN ./configure --enable-seccomp
RUN make -j

CMD make test
