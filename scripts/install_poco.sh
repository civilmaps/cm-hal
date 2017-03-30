#!/bin/bash -xv
poco_ver=1.5.3
poco=poco-${poco_ver}-all
poco_tgz=${poco}.tar.gz

mkdir -p pkgs
if [ ! -f pkgs/$poco_tgz ]; then
  cd pkgs
  wget --no-check-certificate -O $poco_tgz http://pocoproject.org/releases/poco-${poco_ver}/$poco_tgz
  cd -
fi

cd pkgs
tar -xvf $poco_tgz

cd $poco

./configure --omit=Data/MySQL,Data/ODBC,Data/SQLite,XML,Zip,NetSSL_OpenSSL,PageCompiler --no-tests --no-samples --shared --poquito
make -j5 
make install
