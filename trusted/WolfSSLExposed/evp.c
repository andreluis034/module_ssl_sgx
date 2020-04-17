#include "maps.h"

void sgx_EVP_PKEY_free(WOLFSSL_EVP_PKEY_IDENTIFIER keyId)
{
	WOLFSSL_EVP_PKEY* pkey = WolfEvpPkeyMapTypeGet(&WolfEvpPkeyMap,	keyId);
	if(pkey == NULL) return;

	WolfEvpPkeyMapTypeRemove		(&WolfEvpPkeyMap,		keyId);
	WolfEvpPkeyMapInverseTypeRemove	(&WolfEvpPkeyMapInverse, pkey);
	wolfSSL_EVP_PKEY_free(pkey);
}