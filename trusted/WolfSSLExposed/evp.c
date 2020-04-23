#include "maps.h"
#include "sgx_tseal.h"


void sgx_EVP_PKEY_free(WOLFSSL_EVP_PKEY_IDENTIFIER keyId)
{
	WOLFSSL_EVP_PKEY* pkey = WolfEvpPkeyMapTypeGet(&WolfEvpPkeyMap,	keyId);
	if(pkey == NULL) return;

	WolfEvpPkeyMapTypeRemove		(&WolfEvpPkeyMap,		keyId);
	WolfEvpPkeyMapInverseTypeRemove	(&WolfEvpPkeyMapInverse, pkey);
	wolfSSL_EVP_PKEY_free(pkey);
}

int sgx_i2d_PrivateKey(WOLFSSL_EVP_PKEY_IDENTIFIER keyId, unsigned char* der, size_t count)
{
	WOLFSSL_EVP_PKEY* pkey = WolfEvpPkeyMapTypeGet(&WolfEvpPkeyMap,	keyId);
	if(pkey == NULL) -1;

	int size = wolfSSL_i2d_PrivateKey(pkey, NULL);
	if (der == NULL) 
		return size + sizeof(sgx_sealed_data_t);

	if (count < size + sizeof(sgx_sealed_data_t))
		return -1;

	if (sgx_is_within_enclave(der, count) != 1)
		return -1;
	
	unsigned char clearTextKey[size];
	unsigned char * clearTextArrayPtr =  clearTextKey;
	wolfSSL_i2d_PrivateKey(pkey, &clearTextArrayPtr);

	if(sgx_seal_data(0, NULL, size, clearTextKey, count, (sgx_sealed_data_t*)der) == SGX_SUCCESS)
	{
		return size + sizeof(sgx_sealed_data_t);
	}

	return -1;

}