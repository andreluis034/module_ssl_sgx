#include "maps.h"
#include <sgx_trts.h>
#include <sgx_tseal.h>

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


int sgx_OBJ_txt2nid(const char *sn)
{
	return wolfSSL_OBJ_txt2nid(sn);
}


int sgx_OBJ_obj2nid(WOLFSSL_ASN1_OBJECT_IDENTIFIER asn1Id)
{
	ASN1_OBJECT* asn1Object = WolfAsn1ObjectMapTypeGet(&WolfAsn1ObjectMap, asn1Id); //  WolfSSLCtxMapTypeGet(&WolfSSLCtxMap, id);
	if (asn1Object == NULL)
	{
		return 0;
	}
	return wolfSSL_OBJ_obj2nid(asn1Object);
}


//https://www.openssl.org/docs/man1.0.2/man3/d2i_SSL_SESSION.html
int sgx_i2d_SSL_SESSION(WOLFSSL_SSL_SESSION_IDENTIFIER sessionId, unsigned char* buffer, size_t length)
{
	WOLFSSL_SESSION* session = MAP_GET(WolfSSLSessionMap, sessionId);
	if (session == NULL)
	{
		return 0;
	}
	int size = wolfSSL_i2d_SSL_SESSION(session, NULL);
	if (buffer == NULL || length == 0)
	{
		return size + sizeof(sgx_sealed_data_t);
	}
	if (length < size + sizeof(sgx_sealed_data_t))
		return -1;

	if (sgx_is_within_enclave(buffer, length) != 1)
		return -1;
	
	unsigned char clearTextSession[size];
	unsigned char * clearTextSessionPtr =  clearTextSession;
	wolfSSL_i2d_SSL_SESSION(session, &clearTextSessionPtr);

	if(sgx_seal_data(0, NULL, size, clearTextSession, length, (sgx_sealed_data_t*)buffer) == SGX_SUCCESS)
	{
		return size + sizeof(sgx_sealed_data_t);
	}

	return -1;
}

WOLFSSL_SSL_SESSION_IDENTIFIER sgx_d2i_SSL_SESSION(WOLFSSL_SSL_SESSION_IDENTIFIER* sessionOut, unsigned char* buffer, size_t length)
{
	unsigned int realLength = length;
	unsigned char realAsn1Buffer[length - sizeof(sgx_sealed_data_t)], *ptr;
	WOLFSSL_SSL_SESSION_IDENTIFIER sessionId = INVALID_IDENTIFIER;
	if (sgx_unseal_data((sgx_sealed_data_t*)buffer,	NULL, NULL, realAsn1Buffer, &realLength) != SGX_SUCCESS)
	{
		return sessionId;
	}
	ptr = realAsn1Buffer;
	WOLFSSL_SESSION* session = wolfSSL_d2i_SSL_SESSION(NULL,(const unsigned char**) &ptr, realLength);
	InsertInMapTwoWay(sessionId, session, WolfSSLSessionMap);

	if(sessionOut != NULL)
	{
		*sessionOut = sessionId;
	}
	return sessionId;
}