See below if building the proxy

To build memcached in your machine from local repo you will have to install
autotools, automake and libevent. In a debian based system that will look
like this

sudo apt-get install autotools-dev
sudo apt-get install automake
sudo apt-get install libevent-dev

After that you can build memcached binary using automake

cd memcached
./autogen.sh
./configure
make
make test

It should create the binary in the same folder, which you can run

./memcached

You can telnet into that memcached to ensure it is up and running

telnet 127.0.0.1 11211
stats

IF BUILDING PROXY, AN EXTRA STEP IS NECESSARY:

cd memcached
cd vendor
./fetch.sh
cd ..
./autogen.sh
./configure --enable-proxy
make
make test
