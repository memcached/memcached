# gcc -g -Wall -Werror -pedantic -o example example.c mcmc.c
PREFIX=/usr/local

all:
	gcc -g -O2 -Wall -Werror -pedantic -o example example.c mcmc.c
	gcc -g -O2 -Wall -Werror -pedantic -c mcmc.c

clean:
	rm -f example mcmc.o

dist: clean

distdir:
