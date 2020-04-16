#include "maps.h"

#define INIT_LOG(X) printf("[+]Init map " #X "\n")
#define INIT_MAP(X) X##TypeInit(&X); INIT_LOG(X)
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
define_two_way_maps_c(WolfSSLCtxMap, WOLFSSL_SSL_CTX_IDENTIFIER, WOLFSSL_CTX*, 	hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfSSLMap, 	WOLFSSL_SSL_IDENTIFIER, 	WOLFSSL*, 		hashKey, equalKeys, NULL, 0)

//BIO
define_two_way_maps_c(WolfBioMap,		WOLFSSL_BIO_IDENTIFIER, 		WOLFSSL_BIO*, 			hashKey, equalKeys, NULL,0)

//DH
define_two_way_maps_c(WolfDhMap,		WOLFSSL_DH_IDENTIFIER, 			WOLFSSL_DH*, 		hashKey, equalKeys, NULL,0)

//EVP_PKEY
define_two_way_maps_c(WolfEvpPkeyMap, 	WOLFSSL_EVP_PKEY_IDENTIFIER, 	WOLFSSL_EVP_PKEY*, 	hashKey, equalKeys, NULL,0)


//BASIC_CONSTRAINTS
define_two_way_maps_c(WolfBasicConstraintsMap,	WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER, 		WOLFSSL_BASIC_CONSTRAINTS*, hashKey, equalKeys, NULL, 0)

//ASN1
define_two_way_maps_c(WolfAsn1Map,	WOLFSSL_ASN1_INTEGER_IDENTIFIER, 		WOLFSSL_ASN1_INTEGER*, hashKey, equalKeys, NULL, 0)

//BIGNUM
define_two_way_maps_c(WolfBigNumberMap,	WOLFSSL_BIGNUM_IDENTIFIER, 		WOLFSSL_BIGNUM*, hashKey, equalKeys, NULL, 0)

//x509
define_two_way_maps_c(WolfX509Map,			WOLFSSL_X509_IDENTIFIER, 					WOLFSSL_X509*, 				hashKey, equalKeys, NULL, 0)
define_two_way_maps_c(WolfX509NameEntryMap,	WOLFSSL_X509_NAME_ENTRY_IDENTIFIER, 		WOLFSSL_X509_NAME_ENTRY*, 	hashKey, equalKeys, NULL, 0)



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

	//BASIC_CONSTRAINTS
	INIT_MAP(WolfBasicConstraintsMap);
	INIT_MAP(WolfBasicConstraintsMapInverse);

	//ASN1
	INIT_MAP(WolfAsn1Map);
	INIT_MAP(WolfAsn1MapInverse);

	//BIGNUMBER
	INIT_MAP(WolfBigNumberMap);
	INIT_MAP(WolfBigNumberMapInverse);


	//X509
	INIT_MAP(WolfX509Map);
	INIT_MAP(WolfX509MapInverse);
	INIT_MAP(WolfX509NameEntryMap);
	INIT_MAP(WolfX509NameEntryMapInverse);
}