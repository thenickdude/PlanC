.PHONY: all clean release clean-deps

OBJECTS = planc.o adb.o common.o backup.o blocks.o crypto.o properties.o
SUBMODULES = cryptopp/Readme.txt zstr/README.org zlib/README boost/README.md leveldb/README.md snappy/README.md cpp_properties/README.md
BOOST_LIBS = boost/stage/lib/libboost_iostreams.a boost/stage/lib/libboost_program_options.a \
    boost/stage/lib/libboost_filesystem.a boost/stage/lib/libboost_system.a boost/stage/lib/libboost_date_time.a \
    boost/stage/lib/libboost_thread.a boost/stage/lib/libboost_regex.a boost/stage/lib/libboost_serialization.a
STATIC_LIBS = leveldb/build/libleveldb.a cryptopp/libcryptopp.a snappy/build/libsnappy.a $(BOOST_LIBS) zlib/libz.a

UNAME := $(shell uname)

MSYS_VERSION := $(if $(findstring Msys, $(shell uname -o)),$(word 1, $(subst ., ,$(shell uname -r))),0)

ifeq ($(MSYS_VERSION), 0)
# Linux/macOS:
LINK_OS_LIBS =
else
# Windows:
LINK_OS_LIBS = -lcrypt32
endif

ifeq ($(UNAME), Darwin)
# Can't make a fully static build on macOS, but the dynamic version works nicely anyway:
STATIC_OPTIONS =
else
STATIC_OPTIONS = -static -static-libgcc -static-libstdc++
endif
 
all : plan-c

ZLIB_PATH = $(abspath zlib)

$(SUBMODULES) :
	git submodule update --init

cryptopp/libcryptopp.a :
	cd cryptopp && make

leveldb/build/libleveldb.a :
	mkdir -p leveldb/build
	cd leveldb/build && cmake .. -DCMAKE_BUILD_TYPE=Release -DLEVELDB_BUILD_TESTS=OFF -DLEVELDB_BUILD_BENCHMARKS=OFF && cmake --build .

snappy/build/libsnappy.a :
	mkdir -p snappy/build
	cd snappy/build && cmake .. -DCMAKE_CXX_STANDARD=14 -DSNAPPY_BUILD_TESTS=OFF && cmake --build .

zlib/libz.a :
	cd zlib && ./configure && make

cpp_properties/build :
	rm -rf cpp_properties/build
	mkdir cpp_properties/build
	cd cpp_properties/build && BOOST_ROOT=../../boost cmake ..
	cd cpp_properties/build && make

boost/boost/ : zlib/libz.a
	git submodule update --init
	cd boost && ./bootstrap.sh
	echo "using zlib : 1.2.11 : <include>$(ZLIB_PATH) <search>$(ZLIB_PATH) ;" >> boost/project-config.jam
	cd boost && ./b2 headers
	touch -c boost/boost # Ensure it becomes newer than libz so we don't keep rebuilding it

$(BOOST_LIBS) : zlib/libz.a
	cd boost && ./b2 stage variant=release threading=multi link=static address-model=64 --layout=system --build-type=minimal \
		--with-program_options --with-filesystem --with-iostreams --with-date_time --with-system \
		--with-thread --with-regex --with-serialization -s NO_BZIP2=1
	touch -c $(BOOST_LIBS) # Ensure it becomes newer than libz so we don't keep rebuilding it

release : plan-c
	gpg2 --local-user "n.sherlock@gmail.com" --detach-sign -o plan-c.sig plan-c
	tar -zcf plan-c.tar.gz plan-c plan-c.sig

plan-c : $(OBJECTS) $(SUBMODULES) comparator.o $(STATIC_LIBS)
	$(CXX) $(STATIC_OPTIONS) -Wall --std=c++14 -O3 -g3 -o $@ $(OBJECTS) comparator.o $(STATIC_LIBS) -lpthread $(LINK_OS_LIBS)

# Needs to be compiled separately so we can use fno-rtti to be compatible with leveldb:
comparator.o : comparator.cpp
	$(CXX) $(STATIC_OPTIONS) -c -fno-rtti -Wall --std=c++14 -O3 -g3 -o $@ -Ileveldb/include $<

%.o : %.cpp boost/boost/ $(STATIC_LIBS)
	 $(CXX) $(STATIC_OPTIONS) -c -Wall --std=c++14 -O3 -g3 -o $@ -Iboost -Ileveldb/include -Icpp_properties/src/include -Icpp_properties/example/include -Izlib -Izstr/src $<

clean :
	rm -f plan-c plan-c.exe *.o

clean-deps :
	cd cryptopp && make clean || true
	cd boost && ./b2 --clean || true
	cd snappy && make clean || true
	rm -rf leveldb/build
	cd zlib && make clean || true
	cd snappy && make clean || true
