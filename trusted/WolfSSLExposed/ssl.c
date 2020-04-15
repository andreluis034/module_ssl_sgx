#include "maps.h"
#include <sgx_trts.h>
#include "../util_defs.h"






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
	WolfSSLMapTypeAdd		(&WolfSSLMap, 			sslId, ssl);
	WolfSSLMapInverseTypeAdd(&WolfSSLMapInverse, 	ssl, sslId);

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


//TODO FIX this?
int 	sgx_SSL_get_ex_new_index(long argl, char *argp, size_t dataSize)
{
	return wolfSSL_get_ex_new_index(argl, "Second Application Data for SSL", NULL, NULL, NULL);
}

void* 	sgx_SSL_get_ex_data(WOLFSSL_SSL_IDENTIFIER sslId, int appId)
{
	WOLFSSL* ssl =  WolfSSLMapTypeGet(&WolfSSLMap, sslId);
	if (ssl == NULL)
	{
		return NULL;
	}
	return wolfSSL_get_ex_data(ssl, appId);
}

void sgx_SSL_set_ex_data(WOLFSSL_SSL_IDENTIFIER sslId, int appId, void* data)
{
	WOLFSSL* ssl =  WolfSSLMapTypeGet(&WolfSSLMap, sslId);
	if (ssl == NULL)
	{
		return;
	}
	wolfSSL_set_ex_data(ssl, appId, data);
}
