#include "maps.h"
#include "../util_defs.h"

uint64_t sgx_X509_get_ext_d2i(WOLFSSL_X509_IDENTIFIER x509id, int nid)
{
	WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER bcId;
	WOLFSSL_BASIC_CONSTRAINTS* bc;
	WOLFSSL_STACK_IDENTIFIER stackId;
	WOLFSSL_STACK* stack;

	WOLFSSL_X509* x509 =  WolfX509MapTypeGet(&WolfX509Map, x509id); if(x509 == NULL) return INVALID_IDENTIFIER;

	if(nid != NID_basic_constraints && nid != NID_subject_alt_name)
		return INVALID_IDENTIFIER;
	
	void * ret = wolfSSL_X509_get_ext_d2i(x509, nid, NULL, NULL);
	switch (nid)
	{
	case NID_basic_constraints:
		bc = ret;
		RandomUntilNonExistant					(bcId, WolfBasicConstraintsMap);
		WolfBasicConstraintsMapTypeAdd			(&WolfBasicConstraintsMap, bcId, bc);
		WolfBasicConstraintsMapInverseTypeAdd	(&WolfBasicConstraintsMapInverse, bc, bcId);
		return bcId;
	case NID_subject_alt_name:
		stack = ret;
		RandomUntilNonExistant					(stackId, WolfStackMap);
		WolfStackMapTypeAdd(&WolfStackMap, stackId, stack);
		WolfStackMapInverseTypeAdd(&WolfStackMapInverse, stack, stackId);
		return stackId;
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
	WOLFSSL_ASN1_STRING_IDENTIFIER asn1Id = WolfAsn1StringMapInverseTypeGet(&WolfAsn1StringMapInverse, (void*)asn1str);

	if (asn1Id == INVALID_IDENTIFIER)
	{
		RandomUntilNonExistant			(asn1Id, WolfAsn1StringMap);
		WolfAsn1StringMapTypeAdd		(&WolfAsn1StringMap, asn1Id, (void*)asn1str);
		WolfAsn1StringMapInverseTypeAdd	(&WolfAsn1StringMapInverse, (void*)asn1str, asn1Id);
	}
	return asn1Id;
}


int sgx_X509_NAME_print_ex(WOLFSSL_BIO_IDENTIFIER bio_id, WOLFSSL_X509_NAME_IDENTIFIER x509_name_id, int indent, unsigned long flags)
{
	WOLFSSL_X509_NAME* 	x509_name = WolfX509NameMapTypeGet(&WolfX509NameMap, x509_name_id) ;// WolfX509NameEntryMapTypeGet(&WolfX509NameEntryMap, nameEntryId);
	WOLFSSL_BIO* 		bio = WolfBioMapTypeGet(&WolfBioMap, bio_id);
	if(x509_name == NULL || bio == NULL)
		return 0;

	return wolfSSL_X509_NAME_print_ex(bio, x509_name, indent, flags);
}






int sgx_X509_NAME_get_index_by_NID(WOLFSSL_X509_NAME_IDENTIFIER x509NameId, int nid, int pos)
{
	WOLFSSL_X509_NAME* name =  MAP_GET(WolfX509NameMap, x509NameId);
	if(name == NULL)
		return WOLFSSL_FATAL_ERROR;
	return wolfSSL_X509_NAME_get_index_by_NID(name, nid, pos);
}


WOLFSSL_X509_NAME_ENTRY_IDENTIFIER sgx_X509_NAME_get_entry(WOLFSSL_X509_NAME_IDENTIFIER x509NameId, int loc)
{
	WOLFSSL_X509_NAME* name =  MAP_GET(WolfX509NameMap, x509NameId);
	if(name == NULL)
		return INVALID_IDENTIFIER;
	WOLFSSL_X509_NAME_ENTRY* nameEntry = wolfSSL_X509_NAME_get_entry(name, loc);
	if(nameEntry == NULL)
		return INVALID_IDENTIFIER;

	CheckExistingOrCreate(WOLFSSL_X509_NAME_ENTRY_IDENTIFIER, nameEntryId, nameEntry, WolfX509NameEntryMap);

	return nameEntryId;
	
}


void sgx_X509_NAME_ENTRY_remove_from_map(WOLFSSL_X509_NAME_ENTRY_IDENTIFIER entryId)
{
	WOLFSSL_X509_NAME_ENTRY* name =  MAP_GET(WolfX509NameEntryMap, entryId);
	if(name == NULL)
		return;
	MAP_REMOVE_TWO_WAY(WolfX509NameEntryMap, entryId, name);

}

WOLFSSL_X509_NAME_IDENTIFIER sgx_X509_get_subject_name(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 =  WolfX509MapTypeGet(&WolfX509Map, x509id); 
	if(x509 == NULL) 
		return INVALID_IDENTIFIER;
	WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
	

	CheckExistingOrCreate(WOLFSSL_X509_NAME_IDENTIFIER, nameId, name, WolfX509NameMap);

	return nameId;
}

WOLFSSL_X509_NAME_IDENTIFIER sgx_X509_get_issuer_name (WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 =  WolfX509MapTypeGet(&WolfX509Map, x509id); 
	if(x509 == NULL) 
		return INVALID_IDENTIFIER;
	WOLFSSL_X509_NAME* name = wolfSSL_X509_get_issuer_name(x509);
	

	CheckExistingOrCreate(WOLFSSL_X509_NAME_IDENTIFIER, nameId, name, WolfX509NameMap);

	return nameId;
}


WOLFSSL_ASN1_INTEGER_IDENTIFIER		sgx_X509_get_serialNumber(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	if(x509 == NULL)
		return INVALID_IDENTIFIER;
	WOLFSSL_ASN1_INTEGER* serialNumber = wolfSSL_X509_get_serialNumber(x509);

	CheckExistingOrCreate(WOLFSSL_ASN1_INTEGER_IDENTIFIER, serialNumberId, serialNumber, WolfAsn1IntergerMap);

	return serialNumberId;
}

WOLFSSL_ASN1_TIME_IDENTIFIER			sgx_X509_get_notBefore(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	if(x509 == NULL)
		return INVALID_IDENTIFIER;

	WOLFSSL_ASN1_TIME* time = wolfSSL_X509_get_notBefore(x509);
	CheckExistingOrCreate(WOLFSSL_ASN1_TIME_IDENTIFIER, timeId, time, WolfAsn1TimeMap);
	return timeId;
}

WOLFSSL_ASN1_TIME_IDENTIFIER			sgx_X509_get_notAfter(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	if(x509 == NULL)
		return INVALID_IDENTIFIER;
	WOLFSSL_ASN1_TIME* time = wolfSSL_X509_get_notAfter(x509);
	CheckExistingOrCreate(WOLFSSL_ASN1_TIME_IDENTIFIER, timeId, time, WolfAsn1TimeMap);
	return timeId;
}
void sgx_X509_free(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	if(x509 == NULL)
		return;

	MAP_REMOVE_TWO_WAY(WolfX509Map, x509id, x509);
	//Clear all the getters
	REMOVE_TWO_WAY_FROM_POINTER(WolfX509NameMap,		wolfSSL_X509_get_subject_name(x509));
	REMOVE_TWO_WAY_FROM_POINTER(WolfX509NameMap, 		wolfSSL_X509_get_issuer_name(x509));
	REMOVE_TWO_WAY_FROM_POINTER(WolfAsn1IntergerMap, 	wolfSSL_X509_get_serialNumber(x509));
	REMOVE_TWO_WAY_FROM_POINTER(WolfAsn1TimeMap, 		wolfSSL_X509_get_notBefore(x509));
	REMOVE_TWO_WAY_FROM_POINTER(WolfAsn1TimeMap, 		wolfSSL_X509_get_notAfter(x509));

	wolfSSL_X509_free(x509);
}