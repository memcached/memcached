all:
	cd lua && $(MAKE) all CFLAGS="-g" && cd ..
	cd mcmc && $(MAKE) all && cd ..

clean:
	cd lua && $(MAKE) clean && cd ..
	cd mcmc && $(MAKE) clean && cd ..

install: ;

dist: clean
distdir: clean
