.PHONY: all clean release clean-deps

SOURCE = planc.cpp adb.cpp common.cpp backup.cpp blocks.cpp crypto.cpp properties.cpp
SUBMODULES = cryptopp/Readme.txt zstr/README.org zlib/README boost/README.md leveldb/README.md snappy/README.md cpp_properties/README.md
BOOST_LIBS = boost/stage/lib/libboost_iostreams.a boost/stage/lib/libboost_program_options.a \
    boost/stage/lib/libboost_filesystem.a boost/stage/lib/libboost_system.a boost/stage/lib/libboost_date_time.a \
    boost/stage/lib/libboost_thread.a boost/stage/lib/libboost_regex.a boost/stage/lib/libboost_serialization.a
STATIC_LIBS = leveldb/build/libleveldb.a cryptopp/libcryptopp.a snappy/libsnappy.a $(BOOST_LIBS) zlib/libz.a
all : plan-c

# Remove these options if you don't need a static build:
STATIC_OPTIONS = # -static -static-libgcc -static-libstdc++

ZLIB_PATH = $(abspath zlib)

$(SUBMODULES) :
	git submodule update --init

cryptopp/libcryptopp.a :
	cd cryptopp && make

leveldb/build/libleveldb.a :
	mkdir -p leveldb/build
	cd leveldb/build && cmake .. -DCMAKE_BUILD_TYPE=Release -DLEVELDB_BUILD_TESTS=OFF -DLEVELDB_BUILD_BENCHMARKS=OFF && cmake --build .

snappy/libsnappy.a :
	cd snappy && cmake . -DCMAKE_CXX_STANDARD=14 -DSNAPPY_BUILD_TESTS=OFF && make

zlib/libz.a :
	cd zlib && ./configure && make

cpp_properties/build :
	rm -rf cpp_properties/build
	mkdir cpp_properties/build
	cd cpp_properties/build && BOOST_ROOT=../../boost cmake ..
	cd cpp_properties/build && make

boost/boost/ : zlib/libz.a
	cd boost && git submodule update --init && ./bootstrap.sh
	echo "using zlib : 1.2.11 : <include>$(ZLIB_PATH) <search>$(ZLIB_PATH) ;" >> boost/project-config.jam
	cd boost && ./b2 headers

$(BOOST_LIBS) : zlib/libz.a
	cd boost && ./b2 stage --with-program_options --with-filesystem --with-iostreams --with-date_time --with-system --with-thread --with-regex --with-serialization -s NO_BZIP2=1

release : plan-c
	gpg2 --local-user "n.sherlock@gmail.com" --detach-sign -o plan-c.sig plan-c
	tar -zcf plan-c.tar.gz plan-c plan-c.sig

plan-c : $(SOURCE) comparator.o $(SUBMODULES) $(STATIC_LIBS) boost/boost/
	$(CXX) $(STATIC_OPTIONS) -Wall --std=c++14 -O3 -g3 -o $@ -Iboost -Ileveldb/include -Icpp_properties/src/include -Icpp_properties/example/include -Izlib -Izstr/src $(SOURCE) comparator.o $(STATIC_LIBS) -lpthread

# Needs to be compiled separately so we can use fno-rtti to be compatible with leveldb:
comparator.o : comparator.cpp
	$(CXX) $(STATIC_OPTIONS) -c -fno-rtti -Wall --std=c++14 -O3 -g3 -o $@ -Ileveldb/include $<

clean :
	rm -f plan-c comparator.o

clean-deps :
	cd cryptopp && make clean || true
	cd boost && ./b2 --clean || true
	cd snappy && make clean || true
	rm -rf leveldb/build
	cd zlib && make clean || true
	cd snappy && make clean || true
