#!/bin/bash -xv
cd ~/Downloads &&  wget -O jsoncpp-src-0.6.0.tar.gz https://sourceforge.net/projects/jsoncpp/files/jsoncpp/0.6.0-rc2/jsoncpp-src-0.6.0-rc2.tar.gz/download && tar zxvf jsoncpp-src-0.6.0.tar.gz
cd jsoncpp-src-0.6.0-rc2 && scons platform=linux-gcc check || fail
cp -r include/json /usr/local/include/
cp libs/linux-gcc-*/libjson_linux-gcc-*.a /usr/local/lib/libjson.a
cp libs/linux-gcc-*/libjson_linux-gcc-*.so /usr/local/lib/libjson.so
