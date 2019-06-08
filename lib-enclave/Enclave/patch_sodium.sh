#!/bin/bash

wget -qO- https://github.com/jedisct1/libsodium/releases/download/1.0.12/libsodium-1.0.12.tar.gz | tar xvz
cd libsodium-1.0.12
cd src/libsodium
patch -p0 < ../../../libsodium.patch
cd ../..
./configure
cd ../


