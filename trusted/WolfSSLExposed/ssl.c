#include "ssl.h"
#include <sgx_trts.h>
#define RandomUntilNonExistant(X,map) do{sgx_read_rand((unsigned char*)(&X), sizeof(X));}while(X != 0 && map##TypeGet(&map, X) == 0)

int32_t equalKeys(uint64_t key1, uint64_t key2)
{
	return key1 != key2;
}
uint32_t hashKey(uint64_t key)
{
	uint32_t* keyArr =  (uint32_t*)&key;
	return keyArr[0] ^ keyArr[1];
}

define_map_c(WolfSSLCtxMapType, WOLFSSL_SSL_CTX_IDENTIFIER, WOLFSSL_CTX*, 	hashKey, equalKeys, NULL)
define_map_c(WolfSSLMapType, 	WOLFSSL_SSL_IDENTIFIER, 	WOLFSSL*, 		hashKey, equalKeys, NULL)

WolfSSLCtxMapType 	WolfSSLCtxMap;
WolfSSLMapType 		WolfSSLMap;


WOLFSSL_SSL_IDENTIFIER sgx_SSL_new(WOLFSSL_SSL_CTX_IDENTIFIER id)
{
	WOLFSSL_CTX* ctx =  WolfSSLCtxMapTypeGet(&WolfSSLCtxMap, id);
	if (ctx == NULL)
	{
		return 0;
	}
	
	WOLFSSL* ssl = wolfSSL_new(ctx);
	if (ssl != NULL)
	{
		return 0;
	}
	
	WOLFSSL_SSL_IDENTIFIER sslId;
	RandomUntilNonExistant(sslId, WolfSSLMap);
	WolfSSLMapTypeAdd(&WolfSSLMap, sslId, ssl);

	return sslId;
}

void initMaps()
{
	WolfSSLCtxMapTypeInit(&WolfSSLCtxMap);
}