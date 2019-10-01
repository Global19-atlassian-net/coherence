# Welcome to (Cryptoserver) - (DEPRECATED)
<pre>
 _______  _____  _     _ _______  ______ _______ __   _ _______ _______
 |       |     | |_____| |______ |_____/ |______ | \  | |       |______
 |_____  |_____| |     | |______ |    \_ |______ |  \_| |_____  |______

 </pre>

"Privacy is the power to selectively reveal oneself to the world". Eric Hughes
- https://www.activism.net/cypherpunk/manifesto.html
- http://www.coderfreedom.org/
- https://pastebin.com/t6B6fhcv

# Coherence

"Suitable connection or dependence, consistency" (in narrative or argument), also more literally "act or state of sticking or cleaving of one thing to another". 


## Abstract
The future of data breaches is not encouraging, on 2017 less than 4% of data breaches the cryptography became the data stolen into data useless, with enterprise options as well as open source options to perform cryptography even so year in year out data breaches grow.

Coherence (ko.eˈɾen.s) presents a new alternative to perform and offload cryptography operations with a focus on interoperability, flexibility and simplicity. Coherence gives an interface for modern cryptographic algorithms which is inspired by web APIs, but being HTTP-less, it is implemented as a TCP non-blocking server with a JSON interface in order to be used by many languages as possible as well as modern applications. Some of the algorithms offered by Coherence are AES and AES candidates, Sosemanuk, SHA* family, HMAC, DH, RSA, DSA, ECC, NTRU.

**Becoming data breaches into data useless**

## This branch

In this branch  aims to integrate postquatum algorithms and homomorphic encryption, pairing based cryptography , as well as new 
features. In master branch we include qTesla as previous feature from this branch.

## Experimental Features

#### KEM
* NTRU
* Kyber 
* Newnope
* Saber
* Sike

#### SIGN
* Qtesla
* Dilithium

## Quickstart (Docker)

* wget https://raw.githubusercontent.com/liesware/coherence/experimental/Dockerfile
* docker build -t coherence:experimental .
* docker run -p 6613:6613 -it  coherence:experimental /usr/bin/coherence 0.0.0.0 6613

## Quickstart (Linux)

This version is based on Debian 9

For Debian 9 dependencies:
* apt-get install autoconf automake gcc g++ make libtool git wget unzip xsltproc libssl-dev

_This version is compiled with dynamic libs, so install.sh runs cp_libs.sh to copy the libs to /usr/lib/x86_64-linux-gnu/_

Now compile it:
* wget https://raw.githubusercontent.com/liesware/coherence/experimental/install.sh
* sh install.sh
* cd coherence_git/coherence/coherence02/bin ; ./coherence 0.0.0.0 6613
* Run this code

```python 
#!/usr/bin/env python

import socket
import json
import os,binascii

def sending(message):
	ip = '127.0.0.1'
	port = 6613
	BUFFER_SIZE = 65536
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	s.send(message)
	data = s.recv(BUFFER_SIZE)
        print data
	s.close()
	return data

data_js='{"version":1,"algorithm":"SHA3_512","type":"string","plaintext":"Hello world!"}'
sending(data_js)
```
We are getting SHA3-512 for "Hello world!" string.

## Examples 

_You can use your favorite language, we are using python only for illustrative examples( your language needs to support TCP sockets
and json format)._

 ntru.py  qtesla.py  

The code is very simple and with basic programming knowledge you should be able to understand it. You only need to understand python 
tcp sockets and json format.

## Test
on ~/coherence02/

Terminal 1
* watch python ps_mem.py -p $(pidof coherence)

Terminal 2
* cd bin/ && ./coherence 0.0.0.0 6613

Terminal 3
* cd examples/ && sh all.sh

## Wiki
[RTFW](https://en.wikipedia.org/wiki/RTFM)

Please see https://github.com/liesware/coherence/wiki

## Target

* Be cryptoserver (server dedicated for cryptography)
* Improve security in L7 (Cryptography for webapps)

## Version

Current version Arche.

## Contact

We will be so happy to listent to you, only concise and well-reasoned feedback are welcome. please be critic with yourself before 
writing. 

_coherence 4t liesware d0t com_ 

## Webpage

[Link](https://coherence.liesware.com/)
