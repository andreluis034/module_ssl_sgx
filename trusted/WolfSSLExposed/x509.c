#include "maps.h"
#include "../util_defs.h"

uint64_t sgx_X509_get_ext_d2i(WOLFSSL_X509_IDENTIFIER x509id, int nid)
{
	WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER bcId;
	WOLFSSL_BASIC_CONSTRAINTS* bc;

	WOLFSSL_X509* x509 =  WolfX509MapTypeGet(&WolfX509Map, x509id); if(x509 == NULL) return INVALID_IDENTIFIER;

	if(nid != NID_basic_constraints)
		return INVALID_IDENTIFIER;
	
	void * ret = wolfSSL_X509_get_ext_d2i(x509, nid, NULL, NULL);
	switch (nid)
	{
	case NID_basic_constraints:
		bc = ret;
		RandomUntilNonExistant					(bcId, WolfBasicConstraintsMap);
		WolfBasicConstraintsMapTypeAdd			(&WolfBasicConstraintsMap, bcId, bc);
		WolfBasicConstraintsMapInverseTypeAdd	(&WolfBasicConstraintsMapInverse, bc, bcId);
		/* code */
		break;
	
	default:
		break;
	}
}

//TODO seperate maps for asn objects?
WOLFSSL_ASN1_STRING_IDENTIFIER sgx_X509_NAME_ENTRY_get_data(WOLFSSL_X509_NAME_ENTRY_IDENTIFIER nameEntryId)
{
	WOLFSSL_X509_NAME_ENTRY* nameEntry = WolfX509NameEntryMapTypeGet(&WolfX509NameEntryMap, nameEntryId);
	if(nameEntry == NULL)
		return INVALID_IDENTIFIER;
	
	WOLFSSL_ASN1_STRING* asn1str = wolfSSL_X509_NAME_ENTRY_get_data(nameEntry);
	WOLFSSL_ASN1_STRING_IDENTIFIER asn1Id = WolfAsn1MapInverseTypeGet(&WolfAsn1MapInverse, (void*)asn1str);

	if (asn1Id == INVALID_IDENTIFIER)
	{
		RandomUntilNonExistant			(asn1Id, WolfAsn1Map);
		WolfAsn1MapTypeAdd(&WolfAsn1Map, asn1Id, (void*)asn1str);
		WolfAsn1MapInverseTypeAdd(&WolfAsn1MapInverse, (void*)asn1str, asn1Id);
		/* code */
	}
	


	

}
