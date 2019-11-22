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
make test
make

It should create the binary in the same folder, which you can run

./memcached -p 11233

You can telnet into that memcached to ensure it's up and running

telnet 127.0.0.1 11233
stats
