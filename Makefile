.PHONY: all clean release

SOURCE = planc.cpp adb.cpp common.cpp backup.cpp blocks.cpp crypto.cpp
SUBMODULES = cryptopp zstr boost leveldb snappy
BOOST_LIBS = boost/stage/lib/libboost_iostreams.a boost/stage/lib/libboost_program_options.a boost/stage/lib/libboost_filesystem.a boost/stage/lib/libboost_system.a boost/stage/lib/libboost_date_time.a
STATIC_LIBS = leveldb/out-static/libleveldb.a cryptopp/libcryptopp.a snappy/libsnappy.a $(BOOST_LIBS) zlib/libz.a
all : plan-c

ZLIB_PATH = $(abspath zlib)

$(SUBMODULES) :
	git submodule update --init

cryptopp/libcryptopp.a :
	cd cryptopp && make

leveldb/out-static/libleveldb.a :
	cd leveldb && make

snappy/libsnappy.a :
	cd snappy && cmake . && make

zlib/libz.a :
	cd zlib && ./configure && make

boost/boost/ :
	cd boost && git submodule update --init && ./bootstrap.sh
	cd boost && ./b2 headers

$(BOOST_LIBS) : boost/boost/
	cd boost && ./b2 stage --with-program_options --with-filesystem --with-iostreams --with-date_time -s ZLIB_SOURCE=$(ZLIB_PATH) -s ZLIB_LIBPATH=$(ZLIB_PATH)

release : plan-c
	gpg --local-user 0x8F73A12990A8180D --detach-sign -o plan-c.sig plan-c

plan-c : $(SOURCE) $(SUBMODULES) $(STATIC_LIBS) cryptopp/libcryptopp.a boost/boost/
	$(CXX) -Wall --std=c++11 -O3 -o $@ -Iboost -Ileveldb/include -Izlib $(SOURCE) $(STATIC_LIBS) -lpthread

clean :
	rm -f plan-c
