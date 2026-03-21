all:
	@if [ ! -f lua/Makefile ]; then echo "Missing lua application, run $(CURDIR)/fetch.sh script to download it"; exit 1; fi
	cd lua && $(MAKE) all MYCFLAGS="-g" && cd ..

clean:
	cd lua && $(MAKE) clean && cd ..

install: ;

dist: clean
distdir: clean
