#include "maps.h"
#include <sgx_trts.h>
#include "../util_defs.h"


#define GET_SSL(var_name, id, default_return_value) WOLFSSL* var_name =  WolfSSLMapTypeGet(&WolfSSLMap, id); if(var_name == NULL) return default_return_value



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

int sgx_SSL_get_shutdown(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl =  WolfSSLMapTypeGet(&WolfSSLMap, sslId);
	if (ssl == NULL)
	{
		return 0;
	}
	return  wolfSSL_get_shutdown(ssl);
}


int	sgx_SSL_shutdown(WOLFSSL_SSL_IDENTIFIER sslId)
{
	GET_SSL(ssl, sslId, 0);

	return wolfSSL_shutdown(ssl);
}

WOLFSSL_BIO_IDENTIFIER sgx_SSL_get_wbio(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL_BIO_IDENTIFIER retBioId;
	GET_SSL(ssl, sslId, INVALID_IDENTIFIER);

	BIO* bio = wolfSSL_SSL_get_wbio(ssl);

	if(bio == NULL) return INVALID_IDENTIFIER;

	retBioId = WolfBioMapInverseTypeGet(&WolfBioMapInverse, bio);
	if(retBioId == INVALID_IDENTIFIER)
	{
		RandomUntilNonExistant	(retBioId, WolfBioMap);
		WolfBioMapTypeAdd		(&WolfBioMap, retBioId, bio);
		WolfBioMapInverseTypeAdd(&WolfBioMapInverse, bio, retBioId);
	}
	return retBioId;
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


//TODO FIX argument passing?
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
