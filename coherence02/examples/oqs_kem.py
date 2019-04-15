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
        #print message
	s.close()
	return data


oqs_gen='{"version":1,"algorithm":"","operation":"gen", "parameter":""}'
oqs_encap='{"version":1,"algorithm":"", "operation":"encap", "sharedtext":"", "pubkey":"" ,"parameter":""}'
oqs_decap='{"version":1,"algorithm":"", "operation":"decap", "type":"string" ,"parameter":""}'


def oqs_kem (algorithm, params):
    for i in params:
        answ=json.loads(oqs_gen)
        answ["algorithm"]=algorithm
        answ["parameter"]=i
        print "Send key gen\n"
        data_js_n=sending(json.dumps(answ))
        answ=json.loads(data_js_n)
        #print "Recived: \n" + data_js_n +"\n"
        json1=json.loads(oqs_encap)
        json1["algorithm"]=algorithm
        json1["parameter"]=i
        json1["pubkey"]=answ["pubkey"]
        print "Send message encap"
        data_js_n=sending(json.dumps(json1))
        answ1=json.loads(data_js_n)
        print "Recived: \n" + data_js_n +"\n"
        json2=json.loads(oqs_decap)
        json2["algorithm"]=algorithm
        json2["parameter"]=i
        json2["privkey"]=answ["privkey"]
        json2["sharedtext"]=answ1["sharedtext"]
        print "Send message verify\n"
        data_js_n=sending(json.dumps(json2))
        answ2=json.loads(data_js_n)
        print "Recived: \n" + data_js_n +"\n"
        print answ1["sharedkey"]
        print answ2["sharedkey"]





kem_alg=["BIGQUAKE","KYBER","NEWHOPE","SABER","SIKE"]
big_prm=["bigquake1","bigquake3","bigquake5"]
kyber_prm=["kyber512","kyber768","kyber1024"]
newhope_prm=["newhope512","newhope1024"]
saber_prm=["light","saber","fire"]
sike_prm=["sikep503","sikep751"]

#oqs_kem(kem_alg[0],big_prm)
oqs_kem(kem_alg[1],kyber_prm)
oqs_kem(kem_alg[2],newhope_prm)
oqs_kem(kem_alg[3],saber_prm)
oqs_kem(kem_alg[4],sike_prm)
