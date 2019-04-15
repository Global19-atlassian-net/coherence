#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>
#include <sstream>

#include "params.h"

#include "parse-func.h"
#include "crypt-ntru.h"

extern "C" {
#include "crypt-oqs.h"
}

#include <stdio.h>

using namespace rapidjson;
using namespace  std;


int parse_log(stru_info_log& log_info,string& log_js){
  Clear2json(log_info.req);
  Clear2json(log_info.answ);

  stringstream stream;
  stream<<"{ \"ip\":\""<<log_info.ip<<"\",";
  stream<<"\"timestamp\":"<<log_info.timestamp<<",";
  stream<<"\"exec_time\":"<<log_info.exec_time<<",";
  stream<<"\"total_read\":"<<log_info.total_read<<",";
  stream<<"\"total_write\":"<<log_info.total_write<<",";
  stream<<"\"req\":"<<log_info.req<<",";
  stream<<"\"answ\":"<<log_info.answ<<"}";

  #ifdef DEBUG
  cout<<"Log: "<<stream.str()<<endl;
  #endif

  log_js=stream.str();
  return 0;
}


int PARSING(string& str_json, string& answ_js ){
  Document d;
  stru_param req_val;
  answ_js.clear();
  answ_js="{}";

  if(Parsingjson(d, str_json,req_val,answ_js)!=0)
  return 1;

  if(check_ver(d,req_val,answ_js)!=0)
  return 1;

  if(d.HasMember("algorithm") && d["algorithm"].IsString()){
    req_val.algorithm=d["algorithm"].GetString();
  }
  else{
    req_val.error.clear();
    req_val.error="No algorithm tag or bad algorithm data type ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }

  //STRING/////////////////////////////////////////////////////////////////////
  #ifdef _ntru
  if(strncmp(req_val.algorithm.c_str(), "NTRU",sizeof("NTRU")) == 0){
    parse_ntru(d,req_val,answ_js);
  }
  #endif

  #ifdef _qtesla
  else if(strncmp(req_val.algorithm.c_str(), "QTESLA",sizeof("QTESLA")) == 0){
    parse_oqs_sign(d,req_val,answ_js);
  }
  #endif

  #ifdef _dilithium
  else if(strncmp(req_val.algorithm.c_str(), "DILITHIUM",sizeof("DILITHIUM")) == 0){
    parse_oqs_sign(d,req_val,answ_js);
  }
  #endif

/*
  #ifdef _picnic
  else if(strncmp(req_val.algorithm.c_str(), "PICNIC",sizeof("PICNIC")) == 0){
    parse_oqs_sign(d,req_val,answ_js);
  }
  #endif
*/

  else{
    req_val.error="Bad algorithm";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }

  return 0;
}
