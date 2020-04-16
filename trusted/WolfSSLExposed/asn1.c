#include "maps.h"
#include "../util_defs.h"

WOLFSSL_BIGNUM_IDENTIFIER sgx_ASN1_INTEGER_to_BN(WOLFSSL_ASN1_INTEGER_IDENTIFIER asn1IntId)
{
	WOLFSSL_ASN1_INTEGER* asn1Int =  WolfAsn1MapTypeGet(&WolfAsn1Map, asn1IntId); if(asn1Int == NULL) return INVALID_IDENTIFIER;

	WOLFSSL_BIGNUM* bn = wolfSSL_ASN1_INTEGER_to_BN(asn1Int, NULL);

	WOLFSSL_BIGNUM_IDENTIFIER bnId;
	RandomUntilNonExistant			(bnId, WolfBigNumberMap);
	WolfBigNumberMapTypeAdd			(&WolfBigNumberMap, bnId, bn);
	WolfBigNumberMapInverseTypeAdd	(&WolfBigNumberMapInverse, bn, bnId);

	return bnId;
}

int sgx_ASN1_STRING_print_ex(WOLFSSL_BIO_IDENTIFIER bioId, WOLFSSL_ASN1_STRING_IDENTIFIER asn1strId, unsigned long flags)
{
	WOLFSSL_ASN1_STRING* asn1String = (WOLFSSL_ASN1_STRING*) WolfAsn1MapTypeGet(&WolfAsn1Map, asn1strId); if(asn1String == NULL) return 0;
	WOLFSSL_BIO* bio = WolfBioMapTypeGet(&WolfBioMap, bioId); if(bio == NULL) return 0;

	return wolfSSL_ASN1_STRING_print_ex(bio, asn1String, flags);
}
