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
	if (ssl == NULL)
	{
		return 0;
	}
	
	WOLFSSL_SSL_IDENTIFIER sslId = 0;
	RandomUntilNonExistant(sslId, WolfSSLMap);
	WolfSSLMapTypeAdd(&WolfSSLMap, sslId, ssl);

	return sslId;
}


int sgx_SSL_set_session_id_context(WOLFSSL_SSL_IDENTIFIER sslId, unsigned char*buffer, size_t len)
{
	WOLFSSL* ssl =  WolfSSLMapTypeGet(&WolfSSLMap, sslId);
	if (ssl == NULL)
	{
		return 0;
	}
	
	return wolfSSL_set_session_id_context(ssl, buffer, len);
}

void sgx_SSL_set_app_data(WOLFSSL_SSL_IDENTIFIER sslId, void* arg)
{
	WOLFSSL* ssl =  WolfSSLMapTypeGet(&WolfSSLMap, sslId);
	if (ssl == NULL)
	{
		return;
	}
	wolfSSL_set_app_data(ssl, arg);
}

void sgx_SSL_set_verify_result(WOLFSSL_SSL_IDENTIFIER sslId, long verify_result)
{
	WOLFSSL* ssl =  WolfSSLMapTypeGet(&WolfSSLMap, sslId);
	if (ssl == NULL)
	{
		return;
	}
	wolfSSL_set_verify_result(ssl, verify_result);
}


void initMaps()
{
	WolfSSLCtxMapTypeInit(&WolfSSLCtxMap);
	WolfSSLMapTypeInit(&WolfSSLMap);
}