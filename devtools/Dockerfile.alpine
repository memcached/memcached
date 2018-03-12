FROM alpine:latest

RUN apk update && apk add --no-cache musl-dev libevent-dev libseccomp-dev linux-headers gcc make automake autoconf

ADD . /src
WORKDIR /src

RUN ./autogen.sh
RUN ./configure --enable-seccomp
RUN make -j

CMD make test
