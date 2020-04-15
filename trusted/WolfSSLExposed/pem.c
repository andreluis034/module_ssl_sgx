#include "maps.h"
#include "../util_defs.h"
#include <wolfssl/openssl/pem.h>
WOLFSSL_DH_IDENTIFIER sgx_PEM_read_bio_DHparams(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO*  bio = WolfBioMapTypeGet(&WolfBioMap, bioId);
	if (bio == NULL)
	{
		return 0;
	}
	
	WOLFSSL_DH* dh = wolfSSL_PEM_read_bio_DHparams(bio, NULL, NULL, NULL);

	WOLFSSL_DH_IDENTIFIER dhId = 0;
	RandomUntilNonExistant(dhId, WolfDhMap);
	WolfDhMapTypeAdd		(&WolfDhMap, 		dhId, 	dh);
	WolfDhMapInverseTypeAdd	(&WolfDhMapInverse, dh, 	dhId);

	return dhId;
}


WOLFSSL_EVP_PKEY_IDENTIFIER sgx_PEM_read_bio_PrivateKey(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO*  bio = WolfBioMapTypeGet(&WolfBioMap, bioId);
	if (bio == NULL)
	{
		return 0;
	}

	WOLFSSL_EVP_PKEY* pkey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

	WOLFSSL_EVP_PKEY_IDENTIFIER pKeyId = 0;
	RandomUntilNonExistant(pKeyId, WolfEvpPkeyMap);
	
	WolfEvpPkeyMapTypeAdd			(&WolfEvpPkeyMap, 			pKeyId, pkey);
	WolfEvpPkeyMapInverseTypeAdd	(&WolfEvpPkeyMapInverse, 	pkey, pKeyId);

	return pKeyId;
	
}