#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oqs/oqs.h"


typedef struct magic_s {
	uint8_t val[32];
} magic_t;


//The magic numbers are 32 random values.
//The length of the magic number was chosen arbitrarilly to 32.
magic_t magic = {{0xfa, 0xfa, 0xfa, 0xfa, 0xbc, 0xbc, 0xbc, 0xbc,
                  0x15, 0x61, 0x15, 0x61, 0x15, 0x61, 0x15, 0x61,
                  0xad, 0xad, 0x43, 0x43, 0xad, 0xad, 0x34, 0x34,
                  0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78}};

void OQS_print_hex_string(const char *label, const uint8_t *str, size_t len) {
	printf("%-20s (%4zu bytes):  ", label, len);
	for (size_t i = 0; i < (len); i++) {
		//printf("%02X", ((unsigned char *) (str))[i]);
    printf("%02X", str[i]);
	}
	printf("\n");
}

int search_oqs_param_k(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("parameter")){
    if(check_params(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.algorithm.c_str(), "BIGQUAKE",sizeof("BIGQUAKE"))== 0){

      if(strncmp(req_val.parameter.c_str(), "bigquake1",sizeof("bigquake1")) == 0){
        req_val.paramsq_="BIG_QUAKE_1";
      }
      else if(strncmp(req_val.parameter.c_str(), "bigquake3",sizeof("bigquake3")) == 0){
        req_val.paramsq_="BIG_QUAKE_3";
      }
      else if(strncmp(req_val.parameter.c_str(), "bigquake5",sizeof("bigquake5")) == 0){
        req_val.paramsq_="BIG_QUAKE_5";
      }
      else{
        req_val.error="Bad parameter Big Quake ";
        answ_error(req_val,answ_js);
        return 1;
      }
    }
    else if(strncmp(req_val.algorithm.c_str(), "KYBER",sizeof("KYBER"))== 0){

      if(strncmp(req_val.parameter.c_str(), "kyber512",sizeof("kyber512")) == 0){
        req_val.paramsq_="Kyber512";
      }
      else if(strncmp(req_val.parameter.c_str(), "kyber768",sizeof("kyber768")) == 0){
        req_val.paramsq_="Kyber768";
      }
      else if(strncmp(req_val.parameter.c_str(), "kyber1024",sizeof("kyber1024")) == 0){
        req_val.paramsq_="Kyber1024";
      }
      else{
        req_val.error="Bad parameter Kyber ";
        answ_error(req_val,answ_js);
        return 1;
      }
    }
    else if(strncmp(req_val.algorithm.c_str(), "NEWHOPE",sizeof("NEWHOPE"))== 0){

      if(strncmp(req_val.parameter.c_str(), "newhope512",sizeof("newhope512")) == 0){
        req_val.paramsq_="NewHope-512-CCA-KEM";
      }
      else if(strncmp(req_val.parameter.c_str(), "newhope1024",sizeof("newhope1024")) == 0){
        req_val.paramsq_="NewHope-1024-CCA-KEM";
      }
      else{
        req_val.error="Bad parameter Newhope ";
        answ_error(req_val,answ_js);
        return 1;
      }
    }
    else if(strncmp(req_val.algorithm.c_str(), "SABER",sizeof("SABER"))== 0){

      if(strncmp(req_val.parameter.c_str(), "light",sizeof("light")) == 0){
        req_val.paramsq_="LightSaber-KEM";
      }
      else if(strncmp(req_val.parameter.c_str(), "saber",sizeof("saber")) == 0){
        req_val.paramsq_="Saber-KEM";
      }
      else if(strncmp(req_val.parameter.c_str(), "fire",sizeof("fire")) == 0){
        req_val.paramsq_="FireSaber-KEM";
      }
      else{
        req_val.error="Bad parameter Saber ";
        answ_error(req_val,answ_js);
        return 1;
      }
    }
    else if(strncmp(req_val.algorithm.c_str(), "SIKE",sizeof("SIKE"))== 0){

      if(strncmp(req_val.parameter.c_str(), "sikep503",sizeof("sikep503")) == 0){
        req_val.paramsq_="Sike-p503";
      }
      else if(strncmp(req_val.parameter.c_str(), "sikep751",sizeof("sikep751")) == 0){
        req_val.paramsq_="Sike-p751";
      }
      else{
        req_val.error="Bad parameter Newhope ";
        answ_error(req_val,answ_js);
        return 1;
      }
    }

    else{
      req_val.error.clear();
      req_val.error="Bad algorithm";
      req_val.tag="error";
      Addstr2json(answ_js, req_val.tag, req_val.error);
      #ifdef DEBUG
      cerr << req_val.error;
      #endif
      return 1;
    }

  }
  else{
    req_val.error.clear();
    req_val.error="Not parameter for algorithm";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }

  return 0;
}

////////////////////////////////////////////////////////////////////////////////

int OQS_KEM_TEST(string& paramsq_ ,string& privkey, string& pubkey, string& error){

  	OQS_KEM *kem = NULL;
  	uint8_t *public_key = NULL;
  	uint8_t *secret_key = NULL;
  	uint8_t *ciphertext = NULL;
  	uint8_t *shared_secret_e = NULL;
  	uint8_t *shared_secret_d = NULL;
  	OQS_STATUS rc, ret = OQS_ERROR;
  	int rv;

  	//The magic numbers are 32 random values.
  	//The length of the magic number was chosen arbitrarilly to 32.

  	kem = OQS_KEM_new(paramsq_.c_str());
  	if (kem == NULL) {
  		return OQS_SUCCESS;
  	}

  	printf("================================================================================\n");
  	printf("Sample computation for KEM %s\n", kem->method_name);
  	printf("================================================================================\n");

  	public_key = malloc(kem->length_public_key + sizeof(magic_t));
  	secret_key = malloc(kem->length_secret_key + sizeof(magic_t));
  	ciphertext = malloc(kem->length_ciphertext + sizeof(magic_t));
  	shared_secret_e = malloc(kem->length_shared_secret + sizeof(magic_t));
  	shared_secret_d = malloc(kem->length_shared_secret + sizeof(magic_t));

  	//Set the magic numbers
  	memcpy(public_key + kem->length_public_key, magic.val, sizeof(magic_t));
  	memcpy(secret_key + kem->length_secret_key, magic.val, sizeof(magic_t));
  	memcpy(ciphertext + kem->length_ciphertext, magic.val, sizeof(magic_t));
  	memcpy(shared_secret_e + kem->length_shared_secret, magic.val, sizeof(magic_t));
  	memcpy(shared_secret_d + kem->length_shared_secret, magic.val, sizeof(magic_t));

  	if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) || (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
  		fprintf(stderr, "ERROR: malloc failed\n");
  		return OQS_ERROR;
  	}

  	rc = OQS_KEM_keypair(kem, public_key, secret_key);
  	if (rc != OQS_SUCCESS) {
  		fprintf(stderr, "ERROR: OQS_KEM_keypair failed\n");
  		return OQS_ERROR;
  	}
    OQS_print_hex_string("ciphertextO", ciphertext, kem->length_ciphertext + sizeof(magic_t));
    //memset (ciphertext,'\x00',sizeof(ciphertext));

  	rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
  	if (rc != OQS_SUCCESS) {
  		fprintf(stderr, "ERROR: OQS_KEM_encaps failed\n");
  		return OQS_ERROR;
  	}

    OQS_print_hex_string("ciphertextA", ciphertext, kem->length_ciphertext + sizeof(magic_t));


  	rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
  	if (rc != OQS_SUCCESS) {
  		fprintf(stderr, "ERROR: OQS_KEM_decaps failed\n");
  		return OQS_ERROR;
  	}
    OQS_print_hex_string("ciphertextB", ciphertext, kem->length_ciphertext + sizeof(magic_t));

  	rv = memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret);
  	if (rv != 0) {
  		fprintf(stderr, "ERROR: shared secrets are not equal\n");
  		return OQS_ERROR;
  	} else {
  		printf("shared secrets are equal\n");
  	}
    OQS_print_hex_string("shared_secret_e", shared_secret_e, kem->length_shared_secret);
    OQS_print_hex_string("shared_secret_d", shared_secret_d, kem->length_shared_secret);
    OQS_print_hex_string("public_key", public_key, kem->length_public_key + sizeof(magic_t));
    OQS_print_hex_string("secret_key", secret_key, kem->length_secret_key + sizeof(magic_t));
    OQS_print_hex_string("ciphertext", ciphertext, kem->length_ciphertext + sizeof(magic_t));

  	rv = memcmp(public_key + kem->length_public_key, magic.val, sizeof(magic_t));
  	rv |= memcmp(secret_key + kem->length_secret_key, magic.val, sizeof(magic_t));
  	rv |= memcmp(ciphertext + kem->length_ciphertext, magic.val, sizeof(magic_t));
  	rv |= memcmp(shared_secret_e + kem->length_shared_secret, magic.val, sizeof(magic_t));
  	rv |= memcmp(shared_secret_d + kem->length_shared_secret, magic.val, sizeof(magic_t));
  	if (rv != 0) {
  		fprintf(stderr, "ERROR: Magic numbers do not match\n");
  		return OQS_ERROR;
  	}

  	ret = OQS_SUCCESS;

  	if (kem != NULL) {
  		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
  		OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
  		OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
  	}
  	OQS_MEM_insecure_free(public_key);
  	OQS_MEM_insecure_free(ciphertext);
  	OQS_KEM_free(kem);

  	return ret;
}

////////////////////////////////////////////////////////////////////////////////
int OQS_KEM_DECAP(string& paramsq_ ,string& privkey, string& sharedtext, string& sharedkey ,string& error){

  OQS_KEM *kem = NULL;
  uint8_t *secret_key = NULL;
  uint8_t *ciphertext = NULL;
  uint8_t *shared_secret_d = NULL;
  OQS_STATUS rc, ret = OQS_ERROR;
  int rv;
  string priv_bin,sharedtext_bin;

  kem = OQS_KEM_new(paramsq_.c_str());
  if (kem == NULL) {
    return OQS_SUCCESS;
  }

  secret_key = malloc(kem->length_secret_key + sizeof(magic_t));
  ciphertext = malloc(kem->length_ciphertext + sizeof(magic_t));
  shared_secret_d = malloc(kem->length_shared_secret + sizeof(magic_t));

  //Set the magic numbers
  memcpy(secret_key + kem->length_secret_key, magic.val, sizeof(magic_t));
  memcpy(ciphertext + kem->length_ciphertext, magic.val, sizeof(magic_t));
  memcpy(shared_secret_d + kem->length_shared_secret, magic.val, sizeof(magic_t));

  if ((secret_key == NULL) || (ciphertext == NULL) || (shared_secret_d == NULL)) {
    error="ERROR: malloc failed\n";
    return OQS_ERROR;
  }

  StringSource(privkey, true, new HexDecoder(new StringSink(priv_bin)));
  memcpy(secret_key, priv_bin.data(),(kem->length_secret_key + sizeof(magic_t)));

  StringSource(sharedtext, true, new HexDecoder(new StringSink(sharedtext_bin)));
  memcpy(ciphertext, sharedtext_bin.data(),(kem->length_ciphertext + sizeof(magic_t)));

  rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
  if (rc != OQS_SUCCESS) {
    error="ERROR: OQS_KEM_decaps failed\n";
    return OQS_ERROR;
  }

  int i=0;
  char key_hex[4];

  for (i = 0; i < kem->length_shared_secret + sizeof(magic_t); i++){
    snprintf(key_hex,4,"%02X", shared_secret_d[i]);
    sharedkey+=key_hex;
  }

  //#ifdef DEBUG
  OQS_print_hex_string("shared_secret_d", shared_secret_d, kem->length_shared_secret);
  OQS_print_hex_string("secret_key", secret_key, kem->length_secret_key + sizeof(magic_t));
  OQS_print_hex_string("ciphertext", ciphertext, kem->length_ciphertext + sizeof(magic_t));
  //#endif

  return 0;
}



int OQS_KEM_ENCAP(string& paramsq_ ,string& pubkey, string& sharedtext, string& sharedkey ,string& error){

  OQS_KEM *kem = NULL;
  uint8_t *public_key = NULL;
  uint8_t *ciphertext = NULL;
  uint8_t *shared_secret_e = NULL;
  OQS_STATUS rc, ret = OQS_ERROR;
  int rv;
  string pub_bin;

  kem = OQS_KEM_new(paramsq_.c_str());
  if (kem == NULL) {
    return OQS_SUCCESS;
  }

  public_key = malloc(kem->length_public_key + sizeof(magic_t));
  ciphertext = malloc(kem->length_ciphertext + sizeof(magic_t));
  shared_secret_e = malloc(kem->length_shared_secret + sizeof(magic_t));

  //Set the magic numbers
  memcpy(public_key + kem->length_public_key, magic.val, sizeof(magic_t));
  memcpy(ciphertext + kem->length_ciphertext, magic.val, sizeof(magic_t));
  memcpy(shared_secret_e + kem->length_shared_secret, magic.val, sizeof(magic_t));

  if ((public_key == NULL) || (ciphertext == NULL) || (shared_secret_e == NULL)) {
    error="ERROR: malloc failed\n";
    return OQS_ERROR;
  }

  StringSource(pubkey, true, new HexDecoder(new StringSink(pub_bin)));
  memcpy(public_key, pub_bin.data(),(kem->length_public_key + sizeof(magic_t)));

  rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
  if (rc != OQS_SUCCESS) {
    error="ERROR: OQS_KEM_encaps failed\n";
    return OQS_ERROR;
  }

  int i=0;
  char key_hex[4];

  for (i = 0; i < kem->length_shared_secret + sizeof(magic_t); i++){
    snprintf(key_hex,4,"%02X", shared_secret_e[i]);
    sharedkey+=key_hex;
  }

  for (i = 0; i < kem->length_ciphertext + sizeof(magic_t); i++){
    snprintf(key_hex,4,"%02X", ciphertext[i]);
    sharedtext+=key_hex;
  }

  #ifdef DEBUG
  OQS_print_hex_string("shared_secret_e", shared_secret_e, kem->length_shared_secret);
  OQS_print_hex_string("public_key", public_key, kem->length_public_key + sizeof(magic_t));
  OQS_print_hex_string("ciphertext", ciphertext, kem->length_ciphertext + sizeof(magic_t));
  #endif

  return 0;
}

int OQS_KEM_GEN(string& paramsq_ ,string& privkey, string& pubkey, string& error){

    	OQS_KEM *kem = NULL;
    	uint8_t *public_key = NULL;
    	uint8_t *secret_key = NULL;
    	OQS_STATUS rc, ret = OQS_ERROR;
    	int rv;

    	kem = OQS_KEM_new(paramsq_.c_str());
    	if (kem == NULL) {
    		return OQS_SUCCESS;
    	}

    	public_key = malloc(kem->length_public_key + sizeof(magic_t));
    	secret_key = malloc(kem->length_secret_key + sizeof(magic_t));

    	//Set the magic numbers
    	memcpy(public_key + kem->length_public_key, magic.val, sizeof(magic_t));
    	memcpy(secret_key + kem->length_secret_key, magic.val, sizeof(magic_t));

    	if ((public_key == NULL) || (secret_key == NULL)) {
    		error= "ERROR: malloc failed\n";
    		return OQS_ERROR;
    	}

    	rc = OQS_KEM_keypair(kem, public_key, secret_key);
    	if (rc != OQS_SUCCESS) {
    		error="ERROR: OQS_KEM_keypair failed\n";
    		return OQS_ERROR;
    	}

      int i=0;
      char key_hex[4];
      //char pub_key_ex[(kem->length_secret_key + sizeof(magic_t))*2];
      //memset(pub_key_ex, 0, sizeof pub_key_ex);
      //char priv_key_ex[(kem->length_public_key + sizeof(magic_t))*2];
      //memset(priv_key_ex,0,sizeof priv_key_ex);

      for (i = 0; i < kem->length_public_key + sizeof(magic_t); i++){
        snprintf(key_hex,4,"%02X", public_key[i]);
        //strcat(pub_key_ex, key_hex);
        pubkey+=key_hex;
      }

      for (i = 0; i < kem->length_secret_key + sizeof(magic_t); i++){
        //printf("%02X", secret_key[i]);
        snprintf(key_hex,4,"%02X", secret_key[i]);
        //strcat(priv_key_ex, key_hex);
        privkey+=key_hex;
      }

      #ifdef DEBUG
      OQS_print_hex_string("public_key", public_key, kem->length_public_key + sizeof(magic_t));
      OQS_print_hex_string("secret_key", secret_key, kem->length_secret_key + sizeof(magic_t));
      #endif

      if (kem != NULL) {
    		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    	}
    	OQS_MEM_insecure_free(public_key);
    	OQS_KEM_free(kem);

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
int parse_oqs_kem_decap(Document& d, stru_param& req_val, string& answ_js) {
  if(d.HasMember("privkey")&&d.HasMember("sharedtext")){
    if(check_keys(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not pubkey tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  OQS_KEM_DECAP(req_val.paramsq_,req_val.privkey ,req_val.sharedtext, req_val.sharedkey, req_val.error);

  req_val.tag.clear();
  req_val.tag="algorithm";
  Addstr2json(answ_js, req_val.tag, req_val.algorithm);
  req_val.tag.clear();
  req_val.tag="parameter";
  Addstr2json(answ_js, req_val.tag, req_val.parameter);
  req_val.tag.clear();
  req_val.tag="sharedkey";
  Addstr2json(answ_js, req_val.tag, req_val.sharedkey);
  req_val.tag.clear();
  req_val.tag="error";
  Addstr2json(answ_js, req_val.tag, req_val.error);

  return 0;
}



int parse_oqs_kem_encap(Document& d, stru_param& req_val, string& answ_js) {
  if(d.HasMember("pubkey")){
    if(check_keys(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not pubkey tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  OQS_KEM_ENCAP(req_val.paramsq_,req_val.pubkey ,req_val.sharedtext, req_val.sharedkey, req_val.error);

  req_val.tag.clear();
  req_val.tag="algorithm";
  Addstr2json(answ_js, req_val.tag, req_val.algorithm);
  req_val.tag.clear();
  req_val.tag="parameter";
  Addstr2json(answ_js, req_val.tag, req_val.parameter);
  req_val.tag.clear();
  req_val.tag="sharedkey";
  Addstr2json(answ_js, req_val.tag, req_val.sharedkey);
  req_val.tag.clear();
  req_val.tag="sharedtext";
  Addstr2json(answ_js, req_val.tag, req_val.sharedtext);
  req_val.tag.clear();
  req_val.tag="error";
  Addstr2json(answ_js, req_val.tag, req_val.error);

  return 0;
}

int parse_oqs_kem_gen(Document& d, stru_param& req_val, string& answ_js){
  OQS_KEM_GEN(req_val.paramsq_,req_val.privkey, req_val.pubkey, req_val.error);
  keys_anws(req_val,answ_js);

  return 0;
}

int parse_oqs_kem(Document& d, stru_param& req_val, string& answ_js) {
  #ifdef DEBUG
  printf("Good algorithm OQS KEM ");
  #endif

  if(d.HasMember("operation")){
    if(check_ops(d,req_val,answ_js)!=0)
      return 1;
    }
    else{
      req_val.error="Not ops tag ";
      answ_error(req_val,answ_js);
      return 1;
  }

  if(d.HasMember("parameter")){
    if(check_params(d,req_val,answ_js)!=0)
    return 1;
    if(search_oqs_param_k(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error.clear();
    req_val.error="Not parameter tag";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }

  OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);

  if(strncmp(req_val.operation.c_str(), "gen",sizeof("gen")) == 0)
    parse_oqs_kem_gen(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "encap",sizeof("encap")) == 0)
    parse_oqs_kem_encap(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "decap",sizeof("decap")) == 0)
    parse_oqs_kem_decap(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;
}
