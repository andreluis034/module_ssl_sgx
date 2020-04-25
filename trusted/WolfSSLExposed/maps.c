#include "maps.h"

#define INIT_LOG(X) printf("[+]Init map " #X "\n")
#define _INIT_MAP(X) X##TypeInit(&X); INIT_LOG(X)
#define INIT_MAP(X)  _INIT_MAP(X); _INIT_MAP(X ## Inverse)
#define define_two_way_maps_c(typeName , keyType, valueType, hashFn, equalFn, defaultValue, defaultValueInverse) define_map_c(typeName ## Type, keyType, valueType, hashFn, equalFn, defaultValue)\
	define_map_c(typeName ## InverseType , valueType, keyType, hashFn ## Inverse, equalFn ## Inverse, defaultValueInverse) \
	typeName ## Type typeName; \
	typeName ## InverseType typeName ##Inverse;



int32_t equalKeysInverse(void* key1, void* key2)
{
	return key1 != key2;
}

uint32_t hashKeyInverse(void* key)
{
	uint32_t* keyArr =  (uint32_t*)&key;
	return keyArr[0] ^ keyArr[1];
}

int32_t equalKeys(uint64_t key1, uint64_t key2)
{
	return key1 != key2;
}
uint32_t hashKey(uint64_t key)
{
	uint32_t* keyArr =  (uint32_t*)&key;
	return keyArr[0] ^ keyArr[1];
}

//SSL
define_two_way_maps_c(WolfSSLCtxMap, 		WOLFSSL_SSL_CTX_IDENTIFIER, 		WOLFSSL_CTX*, 		hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfSSLMap, 			WOLFSSL_SSL_IDENTIFIER, 			WOLFSSL*, 			hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfSSLSessionMap, 	WOLFSSL_SSL_SESSION_IDENTIFIER, 	WOLFSSL_SESSION*,	hashKey, equalKeys, NULL, 0)

//BIO
define_two_way_maps_c(WolfBioMap,			WOLFSSL_BIO_IDENTIFIER, 			WOLFSSL_BIO*, 			hashKey, equalKeys, NULL,0)
define_two_way_maps_c(WolfBioMethodMap,		WOLFSSL_BIO_METHOD_IDENTIFIER, 		WOLFSSL_BIO_METHOD*, 	hashKey, equalKeys, NULL,0)

//BIO Callbacks
define_map_c(WolfBioCallbackMapType,		WOLFSSL_BIO_METHOD*, 		void**, hashKeyInverse, equalKeysInverse, NULL);
define_map_c(WolfBioCallbackMap2Type,		WOLFSSL_BIO*, 				void*, hashKeyInverse, equalKeysInverse, NULL);

WolfBioCallbackMapType WolfBioCallbackMap;
WolfBioCallbackMap2Type WolfBioCallbackMap2;


//DH
define_two_way_maps_c(WolfDhMap,		WOLFSSL_DH_IDENTIFIER, 			WOLFSSL_DH*, 		hashKey, equalKeys, NULL,0)

//EVP_PKEY
define_two_way_maps_c(WolfEvpPkeyMap, 	WOLFSSL_EVP_PKEY_IDENTIFIER, 	WOLFSSL_EVP_PKEY*, 	hashKey, equalKeys, NULL,0)


//BASIC_CONSTRAINTS
define_two_way_maps_c(WolfBasicConstraintsMap,	WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER, 		WOLFSSL_BASIC_CONSTRAINTS*, hashKey, equalKeys, NULL, 0)

//ASN1
define_two_way_maps_c(WolfAsn1IntergerMap,	WOLFSSL_ASN1_INTEGER_IDENTIFIER, 		WOLFSSL_ASN1_INTEGER*, 	hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfAsn1StringMap,	WOLFSSL_ASN1_STRING_IDENTIFIER, 		WOLFSSL_ASN1_STRING*, 	hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfAsn1TypeMap,		WOLFSSL_ASN1_TYPE_IDENTIFIER, 			WOLFSSL_ASN1_TYPE*, 	hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfAsn1ObjectMap,	WOLFSSL_ASN1_OBJECT_IDENTIFIER, 		WOLFSSL_ASN1_OBJECT*, 	hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfAsn1TimeMap,		WOLFSSL_ASN1_TIME_IDENTIFIER, 			WOLFSSL_ASN1_TIME*, 	hashKey, equalKeys, NULL, 0)

//BIGNUM
define_two_way_maps_c(WolfBigNumberMap,	WOLFSSL_BIGNUM_IDENTIFIER, 		WOLFSSL_BIGNUM*, hashKey, equalKeys, NULL, 0)

//x509
define_two_way_maps_c(WolfX509Map,			WOLFSSL_X509_IDENTIFIER, 					WOLFSSL_X509*, 				hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfX509NameEntryMap,	WOLFSSL_X509_NAME_ENTRY_IDENTIFIER, 		WOLFSSL_X509_NAME_ENTRY*, 	hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfX509NameMap,		WOLFSSL_X509_NAME_IDENTIFIER, 				WOLFSSL_X509_NAME*, 		hashKey, equalKeys, NULL, 0)

//STACK
define_two_way_maps_c(WolfStackMap,			WOLFSSL_STACK_IDENTIFIER, 			WOLFSSL_STACK*, hashKey, equalKeys, NULL, 0)

//GENERAL NAME
define_two_way_maps_c(WolfGeneralNameMap,			WOLFSSL_GENERAL_NAME_IDENTIFIER, 			WOLFSSL_GENERAL_NAME*, hashKey, equalKeys, NULL, 0)

//Init the maps
void InitMaps()
{
	//SSL
	INIT_MAP(WolfSSLCtxMap);
	INIT_MAP(WolfSSLMap);
	INIT_MAP(WolfSSLSessionMap);

	//BIO
	INIT_MAP(WolfBioMap);
	INIT_MAP(WolfBioMethodMap);

	//BIO Callbacks
	_INIT_MAP(WolfBioCallbackMap);
	_INIT_MAP(WolfBioCallbackMap2);

	//DH
	INIT_MAP(WolfDhMap);
	
	//EVP_PKEY
	INIT_MAP(WolfEvpPkeyMap);

	//BASIC_CONSTRAINTS
	INIT_MAP(WolfBasicConstraintsMap);

	//ASN1
	INIT_MAP(WolfAsn1IntergerMap);
	INIT_MAP(WolfAsn1StringMap);
	INIT_MAP(WolfAsn1TypeMap);
	INIT_MAP(WolfAsn1ObjectMap);
	INIT_MAP(WolfAsn1TimeMap);

	//BIGNUMBER
	INIT_MAP(WolfBigNumberMap);


	//X509
	INIT_MAP(WolfX509Map);
	INIT_MAP(WolfX509NameEntryMap);
	INIT_MAP(WolfX509NameMap);

	//STACK
	INIT_MAP(WolfStackMap);


	//GENERAL NAME
	INIT_MAP(WolfGeneralNameMap);
}