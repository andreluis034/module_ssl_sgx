#include "maps.h"
#include "../util_defs.h"

void sgx_BN_free(WOLFSSL_BIGNUM_IDENTIFIER bnId)
{
	WOLFSSL_BIGNUM* bn =  WolfBigNumberMapTypeGet(&WolfBigNumberMap, bnId); if(bn == NULL) return;
	
	WolfBigNumberMapTypeRemove(&WolfBigNumberMap, bnId);
	WolfBigNumberMapInverseTypeRemove(&WolfBigNumberMapInverse, bn);
	wolfSSL_BN_free(bn);

}

int sgx_BN_to_int(WOLFSSL_BIGNUM_IDENTIFIER bnId, int* result )
{
	char* cp;
	if(result == NULL)
		return 0; 
	WOLFSSL_BIGNUM* bn =  WolfBigNumberMapTypeGet(&WolfBigNumberMap, bnId); if(bn == NULL) return 0;

    if ((cp = wolfSSL_BN_bn2dec(bn)) == NULL)
		return 0;
	*result = atoi(cp);

	wolfSSL_Free(cp);
	return 1;
}

int sgx_BN_bn2dec(WOLFSSL_BIGNUM_IDENTIFIER bnId, char* buffer, int length)
{
	WOLFSSL_BIGNUM* bn = MAP_GET(WolfBigNumberMap, bnId);
	char* inDec = wolfSSL_BN_bn2dec(bn);
	if (inDec == NULL)
		return -1;
	
	int strLength = strlen(inDec);
	if(buffer == NULL || length  == 0)
	{
		free(inDec);
		return strLength;
	}

	if (length <= strLength)
	{
		free(inDec);
		return -1;
	}
	memset(buffer, 0, length);
	memcpy(buffer, inDec, strLength);
	free(inDec);
	return strLength;	

}
