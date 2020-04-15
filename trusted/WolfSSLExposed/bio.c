#include "maps.h"
#include <sgx_trts.h>
#include "../util_defs.h"
#include "../Enclave_t.h"

WOLFSSL_BIO_METHOD* GetBioMethod(enum BIO_TYPE type)
{
	switch (type)
	{
	case WOLFSSL_BIO_BUFFER:
		return wolfSSL_BIO_f_buffer();
	case WOLFSSL_BIO_SOCKET :
		return wolfSSL_BIO_s_socket();
	case WOLFSSL_BIO_SSL    :
		return wolfSSL_BIO_f_ssl();
	case WOLFSSL_BIO_MEMORY :
		return wolfSSL_BIO_s_mem();
	case WOLFSSL_BIO_BIO    :
		return wolfSSL_BIO_s_bio();
	case WOLFSSL_BIO_FILE   :
		return NULL;
		//return wolfSSL_BIO_s_file();
	case WOLFSSL_BIO_BASE64 :
		return wolfSSL_BIO_f_base64();
	case WOLFSSL_BIO_MD     :
		return wolfSSL_BIO_f_md();
	default:
		return NULL;
	}
}

WOLFSSL_BIO_IDENTIFIER sgx_BIO_new_file(const char *filename, const char *mode)
{
	uint64_t filePtr;
	int len;
	char buffer[1024];
	if(strcmp(mode, "r") != 0)
		return 0; //Only read implemented


	//sgx_status_t SGX_CDECL ocall_fopen(uint64_t* retval, const char* file, const char* mode)

	ocall_fopen(&filePtr, filename, mode);
	if(filePtr == 0)	return 0;

	WOLFSSL_BIO*  bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());//wolfSSL_BIO_new_file(filename, mode);


	ocall_fread(&len, buffer, 1, sizeof(buffer), filePtr);

	while(len > 0 )
	{
		wolfSSL_BIO_write(bio, buffer, len);
		len = 0;
		ocall_fread(&len, buffer, 1, sizeof(buffer), filePtr);
	}
	ocall_fclose(filePtr);

	WOLFSSL_BIO_IDENTIFIER bioId = 0;
	RandomUntilNonExistant(bioId, WolfBioMap);

	WolfBioMapTypeAdd		(&WolfBioMap, bioId, bio);
	WolfBioMapInverseTypeAdd(&WolfBioMapInverse, bio, bioId);

	return bioId;
}


WOLFSSL_BIO_IDENTIFIER sgx_BIO_new(WOLFSSL_BIO_METHOD_IDENTIFIER methodId)
{
	WOLFSSL_BIO_METHOD* bioMethod = GetBioMethod((enum BIO_TYPE)methodId);
	if(bioMethod == NULL)
	{
		return 0;
	}
	WOLFSSL_BIO*  bio  =  wolfSSL_BIO_new(bioMethod);
	WOLFSSL_BIO_IDENTIFIER bioId = 0;
	RandomUntilNonExistant(bioId, WolfBioMap);
	WolfBioMapTypeAdd		(&WolfBioMap, bioId, bio);
	WolfBioMapInverseTypeAdd(&WolfBioMapInverse, bio, bioId);

	return bioId;
}

WOLFSSL_BIO_IDENTIFIER sgx_BIO_push(WOLFSSL_BIO_IDENTIFIER bioId1, WOLFSSL_BIO_IDENTIFIER bioId2)
{
	WOLFSSL_BIO* bio1 = WolfBioMapTypeGet(&WolfBioMap, bioId1);
	WOLFSSL_BIO* bio2 = WolfBioMapTypeGet(&WolfBioMap, bioId2);
	
	if(bio1 == NULL || bio2 == NULL) return INVALID_IDENTIFIER;

	WOLFSSL_BIO* bio3 = wolfSSL_BIO_push(bio1, bio2);

	WOLFSSL_BIO_IDENTIFIER retBioId  = WolfBioMapInverseTypeGet(&WolfBioMapInverse, bio3);
	
	if (retBioId) return retBioId;

	RandomUntilNonExistant(retBioId, WolfBioMap);
	WolfBioMapTypeAdd		(&WolfBioMap, retBioId, bio3);
	WolfBioMapInverseTypeAdd(&WolfBioMapInverse, bio3, retBioId);

	return retBioId;
}

WOLFSSL_EVP_PKEY_IDENTIFIER sgx_d2i_PrivateKey_bio(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = WolfBioMapTypeGet(&WolfBioMap, bioId);
	if(bio == NULL) return INVALID_IDENTIFIER;

	WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PrivateKey_bio(bio, NULL);

	WOLFSSL_EVP_PKEY_IDENTIFIER keyId = 0;
	
	RandomUntilNonExistant		(keyId, WolfEvpPkeyMap);
	WolfEvpPkeyMapTypeAdd		(&WolfEvpPkeyMap, 			keyId, pkey);
	WolfEvpPkeyMapInverseTypeAdd(&WolfEvpPkeyMapInverse, 	pkey, keyId);
}



int sgx_BIO_free(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = WolfBioMapTypeGet(&WolfBioMap, bioId);
	if(bio == NULL)
	{
		return 0;
	}

	WolfBioMapTypeRemove(&WolfBioMap, bioId);
	WolfBioMapInverseTypeRemove(&WolfBioMapInverse, bio);
	return wolfSSL_BIO_free(bio);
}



int sgx_BIO_free_all(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = WolfBioMapTypeGet(&WolfBioMap, bioId);
    while (bio) {
		bioId = WolfBioMapInverseTypeGet(&WolfBioMapInverse, bio);

        WOLFSSL_BIO* next = bio->next;
		sgx_BIO_free(bioId);
		//wolfSSL_BIO_free(bio);
        bio = next;
    }
    return 0;

}


WOLFSSL_BIO_METHOD_IDENTIFIER sgx_BIO_f_base64()
{
	return WOLFSSL_BIO_BASE64;
}
