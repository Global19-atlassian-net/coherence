#!/bin/bash

cp lib/libuv/.libs/libuv.so.1.0.0 /lib64/libuv.so.1
cp lib/cryptopp/libcryptopp.so.8.* /lib64/libcryptopp.so.8
cp lib/libntru/libntru.so /lib64/
cp lib/liboqs/.libs/liboqs.so.0.0.0 /lib64/liboqs.so.0
cp lib/argon2/libargon2.so.1 /lib64/
ls -lha /lib64/libuv.so.1
ls -lha /lib64/libcryptopp.so.8
ls -lha /lib64/libntru.so
ls -lha /lib64/liboqs.so.0
ls -lha /lib64/libargon2.so.1 
