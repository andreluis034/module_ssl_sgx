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


WOLFSSL_BIO_METHOD_IDENTIFIER sgx_BIO_f_base64()
{
	return WOLFSSL_BIO_BASE64;
}
