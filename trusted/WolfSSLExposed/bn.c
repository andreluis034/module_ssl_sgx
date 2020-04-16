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