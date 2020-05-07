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

long sgx_SSL_get_shutdown(WOLFSSL_SSL_IDENTIFIER sslId)
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

int sgx_SSL_set_session_id_context(WOLFSSL_SSL_IDENTIFIER sslId, unsigned char*buffer, size_t len)
{
	WOLFSSL* ssl =  WolfSSLMapTypeGet(&WolfSSLMap, sslId);
	if (ssl == NULL)
	{
		return 0;
	}
	
	return wolfSSL_set_session_id_context(ssl, buffer, len);
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


void sgx_SSL_set_bio(WOLFSSL_SSL_IDENTIFIER sslId, WOLFSSL_BIO_IDENTIFIER readBioId, WOLFSSL_BIO_IDENTIFIER writeBioId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	WOLFSSL_BIO* rd = MAP_GET(WolfBioMap, readBioId);
	WOLFSSL_BIO* wr = MAP_GET(WolfBioMap, writeBioId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return;
	}
	if(rd == NULL || wr == NULL)
	{
		printf("[WARN][%s] rd(%p) or wr(%p) NULL", __func__, rd, wr);
	}
	wolfSSL_set_bio(ssl, rd, wr);
}


WOLFSSL_BIO_IDENTIFIER sgx_SSL_get_rbio(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return INVALID_IDENTIFIER;
	}
	WOLFSSL_BIO* bio = wolfSSL_SSL_get_rbio(ssl);
	if(bio)
	{
		return MAP_GET(WolfBioMapInverse, bio);
	}
	return INVALID_IDENTIFIER;
}
WOLFSSL_BIO_IDENTIFIER sgx_SSL_get_wbio(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return INVALID_IDENTIFIER;
	}
	WOLFSSL_BIO* bio = wolfSSL_SSL_get_rbio(ssl);
	if(bio)
	{
		return MAP_GET(WolfBioMapInverse, bio);
	}
	return INVALID_IDENTIFIER;
}


int sgx_SSL_read(WOLFSSL_SSL_IDENTIFIER sslId, unsigned char* buffer, int num)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	return wolfSSL_read(ssl, buffer, num);
}
int sgx_SSL_write(WOLFSSL_SSL_IDENTIFIER sslId, const unsigned char* buffer, int num)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	return wolfSSL_write(ssl, buffer, num);
}


int sgx_SSL_get_error(WOLFSSL_SSL_IDENTIFIER sslId, int ret)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	return wolfSSL_get_error(ssl, ret);
}

void sgx_SSL_set_app_data(WOLFSSL_SSL_IDENTIFIER sslId, void* data)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return;
	}
	wolfSSL_set_app_data(ssl, data);
}

void* sgx_SSL_get_app_data(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return NULL;
	}
	return wolfSSL_get_app_data(ssl);
}


long sgx_SSL_total_renegotiations(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	return wolfSSL_total_renegotiations(ssl);
}

#define CHECK_IF_EXISTS_AND_REMOVE(idType, realType, value, map){idType id = value;if(id != INVALID_IDENTIFIER){realType val = MAP_GET(map, id); MAP_REMOVE_TWO_WAY(map, id, val);}}

WOLFSSL_X509_IDENTIFIER sgx_SSL_get_certificate(WOLFSSL_SSL_IDENTIFIER sslId);
WOLFSSL_STACK_IDENTIFIER sgx_SSL_get_peer_cert_chain(WOLFSSL_SSL_IDENTIFIER sslId);
WOLFSSL_X509_IDENTIFIER sgx_SSL_get_peer_certificate(WOLFSSL_SSL_IDENTIFIER sslId);
WOLFSSL_SSL_CIPHER_IDENTIFIER sgx_SSL_get_current_cipher(WOLFSSL_SSL_IDENTIFIER sslId);
WOLFSSL_BIO_IDENTIFIER sgx_SSL_get_rbio(WOLFSSL_SSL_IDENTIFIER sslId);
WOLFSSL_BIO_IDENTIFIER sgx_SSL_get_wbio(WOLFSSL_SSL_IDENTIFIER sslId);

//TODO clean context?
void sgx_SSL_free(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return;
	}


	CHECK_IF_EXISTS_AND_REMOVE(WOLFSSL_X509_IDENTIFIER, 		WOLFSSL_X509*, 		sgx_SSL_get_peer_certificate(sslId),		WolfX509Map);
	CHECK_IF_EXISTS_AND_REMOVE(WOLFSSL_X509_IDENTIFIER, 		WOLFSSL_X509*, 		sgx_SSL_get_certificate(sslId), 			WolfX509Map);
	CHECK_IF_EXISTS_AND_REMOVE(WOLFSSL_STACK_IDENTIFIER, 		WOLFSSL_STACK*, 	sgx_SSL_get_peer_certificate(sslId),		WolfStackMap);
	CHECK_IF_EXISTS_AND_REMOVE(WOLFSSL_SSL_SESSION_IDENTIFIER, 	WOLFSSL_SESSION*, 	sgx_SSL_get_current_cipher(sslId), 			WolfSSLSessionMap);
	CHECK_IF_EXISTS_AND_REMOVE(WOLFSSL_BIO_IDENTIFIER, 			WOLFSSL_BIO*, 		sgx_SSL_get_rbio(sslId), 					WolfBioMap);
	CHECK_IF_EXISTS_AND_REMOVE(WOLFSSL_BIO_IDENTIFIER, 			WOLFSSL_BIO*, 		sgx_SSL_get_wbio(sslId), 					WolfBioMap);
	
/*
	REMOVE_TWO_WAY_FROM_POINTER(WolfSSLSessionMap, wolfSSL_get_current_cipher(ssl));
	REMOVE_TWO_WAY_FROM_POINTER(WolfBioMap, WolfSSL_get_rbio(ssl));
	REMOVE_TWO_WAY_FROM_POINTER(WolfBioMap, WolfSSL_get_wbio(ssl));*/

	return wolfSSL_free(ssl);
}


int sgx_SSL_is_init_finished(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	return wolfSSL_is_init_finished(ssl);
}

int sgx_SSL_in_connect_init(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	return wolfSSL_SSL_in_connect_init(ssl);
}



int sgx_SSL_connect(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	return wolfSSL_connect(ssl);
}


WOLFSSL_X509_IDENTIFIER sgx_SSL_get_peer_certificate(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return INVALID_IDENTIFIER;
	}
	WOLFSSL_X509* x509 = wolfSSL_get_peer_certificate(ssl);// wolfSSL_connect(ssl);
	if(x509 == NULL)
		return INVALID_IDENTIFIER;
		
	
	CheckExistingOrCreate(WOLFSSL_X509_IDENTIFIER, x509id, x509, WolfX509Map);
	
	return x509id;
}

void sgx_SSL_set_shutdown(WOLFSSL_SSL_IDENTIFIER sslId, int opt)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return;
	}

	wolfSSL_set_shutdown(ssl, opt);
}

int sgx_SSL_set_tlsext_host_name(WOLFSSL_SSL_IDENTIFIER sslId, const char* host_name)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return WOLFSSL_FAILURE;
	}
	return wolfSSL_set_tlsext_host_name(ssl, host_name);
}

int sgx_SSL_accept(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return INVALID_IDENTIFIER;
	}
	return wolfSSL_accept(ssl);
}


long sgx_SSL_get_verify_result(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return INVALID_IDENTIFIER;
	}
	return wolfSSL_get_verify_result(ssl);
}

WOLFSSL_X509_IDENTIFIER sgx_SSL_get_certificate(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return INVALID_IDENTIFIER;
	}
	WOLFSSL_X509* x509 = wolfSSL_get_certificate(ssl);// wolfSSL_connect(ssl);
	if(x509 == NULL)
		return INVALID_IDENTIFIER;
		
	
	CheckExistingOrCreate(WOLFSSL_X509_IDENTIFIER, x509id, x509, WolfX509Map);
	return x509id;
}


int sgx_SSL_get_version(WOLFSSL_SSL_IDENTIFIER sslId, char* version, size_t buffer_len)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	const char* _version = wolfSSL_get_version(ssl);
	strncpy(version, _version, buffer_len);
	return 1;

}

int sgx_SSL_session_reused(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	return wolfSSL_session_reused(ssl);
}


WOLFSSL_STACK_IDENTIFIER sgx_SSL_get_peer_cert_chain(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return INVALID_IDENTIFIER;
	}

	void* stack = wolfSSL_get_peer_cert_chain(ssl);
	if(stack == NULL)
		return INVALID_IDENTIFIER;

	CheckExistingOrCreate(WOLFSSL_STACK_IDENTIFIER, stackId, stack, WolfStackMap);

	return stackId;
}

int sgx_SSL_get_servername(WOLFSSL_SSL_IDENTIFIER sslId, uint8_t type, char* buffer, size_t buffer_len)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return 0;
	}
	const char* hostname = wolfSSL_get_servername(ssl, type);
	strncpy(buffer, hostname, buffer_len);
	return 1;
}

WOLFSSL_SSL_SESSION_IDENTIFIER sgx_SSL_get_session(WOLFSSL_SSL_SESSION_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);
	if(ssl == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant sslId 0x%X", __func__, sslId);
		return INVALID_IDENTIFIER;
	}

	WOLFSSL_SESSION* session = wolfSSL_get_session(ssl);
	if(session == NULL)
		return INVALID_IDENTIFIER;

	CheckExistingOrCreate(WOLFSSL_SSL_SESSION_IDENTIFIER, sessionId, session, WolfSSLSessionMap);

	return sessionId;
}



int sgx_SSL_SESSION_get_id(WOLFSSL_SSL_SESSION_IDENTIFIER sessionId, char* buffer, size_t buffer_len)
{
	WOLFSSL_SESSION* session = MAP_GET(WolfSSLSessionMap, sessionId);// wolfSSL_get_session(ssl);
	if(session == NULL)
		return INVALID_IDENTIFIER;
	unsigned int actualSize;
	uint8_t* id = (uint8_t*)wolfSSL_SESSION_get_id(session, &actualSize);
	if (actualSize > buffer_len)
	{
		return 0;
	}
	memcpy(buffer, id, actualSize);
	return actualSize;	
}

unsigned int sgx_SSL_SESSION_get_id_sz(WOLFSSL_SSL_SESSION_IDENTIFIER sessionId)
{
	WOLFSSL_SESSION* session = MAP_GET(WolfSSLSessionMap, sessionId);// wolfSSL_get_session(ssl);
	if(session == NULL)
		return -1;
	unsigned int size;
	wolfSSL_SESSION_get_id(session, &size);
	return size;
}

int sgx_SSL_CIPHER_get_bits(WOLFSSL_SSL_CIPHER_IDENTIFIER cipherId,  int *alg_bits)
{
	WOLFSSL_CIPHER* cipher = MAP_GET(WolfSSLCipherMap, cipherId);
	if(cipher == NULL)
		return 0;

	return wolfSSL_CIPHER_get_bits((const WOLFSSL_CIPHER*)cipher, alg_bits);
}

WOLFSSL_SSL_CIPHER_IDENTIFIER sgx_SSL_get_current_cipher(WOLFSSL_SSL_IDENTIFIER sslId)
{
	WOLFSSL* ssl = MAP_GET(WolfSSLMap, sslId);// wolfSSL_get_session(ssl);
	if(ssl == NULL)
		return INVALID_IDENTIFIER;

	WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
	CheckExistingOrCreate(WOLFSSL_SSL_CIPHER_IDENTIFIER, cipherId, cipher, WolfSSLCipherMap);

	return cipherId;
}

int sgx_SSL_CIPHER_get_name(WOLFSSL_SSL_CIPHER_IDENTIFIER cipherId, char* buffer, int length)
{
	WOLFSSL_CIPHER* cipher = MAP_GET(WolfSSLCipherMap, cipherId);// wolfSSL_get_session(ssl);
	if(cipher == NULL)
		return 0;
	const char* name = wolfSSL_CIPHER_get_name(cipher);
	int strLength = strlen(name);
	if (strLength <= length)
	{
		return 0;// Not enough memory
	}
	memset(buffer, 0, length);
	memcpy(buffer, name, strLength);

	return strLength;
}