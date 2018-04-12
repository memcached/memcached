FROM archlinux/base:latest

RUN pacman -Sy && pacman --noconfirm -S gcc automake autoconf libevent libseccomp git make perl
RUN ln -s /usr/bin/core_perl/prove /usr/bin/prove

ADD . /src
WORKDIR /src

RUN aclocal
RUN autoheader
RUN automake --gnu --add-missing
RUN autoconf

RUN ./configure --enable-seccomp
RUN make -j

CMD make test
