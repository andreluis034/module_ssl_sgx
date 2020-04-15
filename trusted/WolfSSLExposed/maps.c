#include "maps.h"

#define INIT_LOG(X) printf("[+]Init map " #X "\n")
#define INIT_MAP(X) X##TypeInit(&X); INIT_LOG(X)
#define define_two_way_maps_c(typeName , keyType, valueType, hashFn, equalFn, defaultValue, defaultValueInverse) define_map_c(typeName ## Type, keyType, valueType, hashFn, equalFn, defaultValue)\
	define_map_c(typeName ## InverseType , valueType, keyType, hashFn ## Inverse, equalFn ## Inverse, defaultValueInverse)



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
define_two_way_maps_c(WolfSSLCtxMap, WOLFSSL_SSL_CTX_IDENTIFIER, WOLFSSL_CTX*, 	hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfSSLMap, 	WOLFSSL_SSL_IDENTIFIER, 	WOLFSSL*, 		hashKey, equalKeys, NULL, 0)

WolfSSLCtxMapType 	WolfSSLCtxMap;
WolfSSLMapType 		WolfSSLMap;

WolfSSLCtxMapInverseType 	WolfSSLCtxMapInverse;
WolfSSLMapInverseType 		WolfSSLMapInverse;


//BIO
define_two_way_maps_c(WolfBioMap,		WOLFSSL_BIO_IDENTIFIER, 		WOLFSSL_BIO*, 			hashKey, equalKeys, NULL,0)

WolfBioMapType 			WolfBioMap;

WolfBioMapInverseType 			WolfBioMapInverse;

//DH
define_two_way_maps_c(WolfDhMap,		WOLFSSL_DH_IDENTIFIER, 			WOLFSSL_DH*, 		hashKey, equalKeys, NULL,0)

WolfDhMapType WolfDhMap;

WolfDhMapInverseType WolfDhMapInverse;

//EVP_PKEY
define_two_way_maps_c(WolfEvpPkeyMap, 	WOLFSSL_EVP_PKEY_IDENTIFIER, 	WOLFSSL_EVP_PKEY*, 	hashKey, equalKeys, NULL,0)

WolfEvpPkeyMapType WolfEvpPkeyMap;

WolfEvpPkeyMapInverseType WolfEvpPkeyMapInverse;


//Init the maps
void InitMaps()
{
	//SSL
	INIT_MAP(WolfSSLCtxMap);
	INIT_MAP(WolfSSLMap);
	INIT_MAP(WolfSSLCtxMapInverse);
	INIT_MAP(WolfSSLMapInverse);

	//BIO
	INIT_MAP(WolfBioMap);
	INIT_MAP(WolfBioMapInverse);
	
	//DH
	INIT_MAP(WolfDhMap);
	INIT_MAP(WolfDhMapInverse);
	
	//EVP_PKEY
	INIT_MAP(WolfEvpPkeyMap);
	INIT_MAP(WolfEvpPkeyMapInverse);
}