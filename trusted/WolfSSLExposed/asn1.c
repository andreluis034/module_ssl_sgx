#include "maps.h"
#include "../util_defs.h"

WOLFSSL_BIGNUM_IDENTIFIER sgx_ASN1_INTEGER_to_BN(WOLFSSL_ASN1_INTEGER_IDENTIFIER asn1IntId)
{
	WOLFSSL_ASN1_INTEGER* asn1Int =  WolfAsn1IntergerMapTypeGet(&WolfAsn1IntergerMap, asn1IntId); if(asn1Int == NULL) return INVALID_IDENTIFIER;

	WOLFSSL_BIGNUM* bn = wolfSSL_ASN1_INTEGER_to_BN(asn1Int, NULL);

	WOLFSSL_BIGNUM_IDENTIFIER bnId;
	RandomUntilNonExistant			(bnId, WolfBigNumberMap);
	WolfBigNumberMapTypeAdd			(&WolfBigNumberMap, bnId, bn);
	WolfBigNumberMapInverseTypeAdd	(&WolfBigNumberMapInverse, bn, bnId);

	return bnId;
}

int sgx_ASN1_STRING_print_ex(WOLFSSL_BIO_IDENTIFIER bioId, WOLFSSL_ASN1_STRING_IDENTIFIER asn1strId, unsigned long flags)
{
	WOLFSSL_ASN1_STRING* asn1String = WolfAsn1StringMapTypeGet(&WolfAsn1StringMap, asn1strId); if(asn1String == NULL) return 0;
	WOLFSSL_BIO* bio = WolfBioMapTypeGet(&WolfBioMap, bioId); if(bio == NULL) return 0;

	return wolfSSL_ASN1_STRING_print_ex(bio, asn1String, flags);
}


int sgx_ASN1_TYPE_get_type(WOLFSSL_ASN1_TYPE_IDENTIFIER typeId)
{
	WOLFSSL_ASN1_TYPE* asn1type =  WolfAsn1TypeMapTypeGet(&WolfAsn1TypeMap, typeId); if(asn1type == NULL) return 0;

	return asn1type->type;
}


WOLFSSL_ASN1_STRING_IDENTIFIER sgx_ASN1_TYPE_get_string(WOLFSSL_ASN1_TYPE_IDENTIFIER typeId)
{
	WOLFSSL_ASN1_TYPE* asn1type =  WolfAsn1TypeMapTypeGet(&WolfAsn1TypeMap, typeId); if(asn1type == NULL) return INVALID_IDENTIFIER;
	WOLFSSL_ASN1_STRING* asn1str;
	WOLFSSL_ASN1_STRING_IDENTIFIER asn1Id;
	if (asn1type->type == V_ASN1_UTF8STRING)
	{	
		asn1str = asn1type->value.utf8string;
	} 
	else if(asn1type->type == V_ASN1_IA5STRING)
	{
		asn1str = asn1type->value.ia5string;
	}
	asn1Id = WolfAsn1StringMapInverseTypeGet(&WolfAsn1StringMapInverse, asn1str);
	if (asn1Id == INVALID_IDENTIFIER)
	{
		RandomUntilNonExistant			(asn1Id, WolfAsn1StringMap);
		WolfAsn1StringMapTypeAdd		(&WolfAsn1StringMap, asn1Id, asn1str);
		WolfAsn1StringMapInverseTypeAdd	(&WolfAsn1StringMapInverse, asn1str, asn1Id);
	}
	return asn1Id;
}


int sgx_i2a_ASN1_INTEGER(WOLFSSL_BIO_IDENTIFIER bioId, WOLFSSL_ASN1_INTEGER_IDENTIFIER asn1IntId)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
		return -1;
	WOLFSSL_ASN1_INTEGER* asn1Int = MAP_GET(WolfAsn1IntergerMap, asn1IntId);
	if (asn1Int == NULL)
		return -1;
	
	return wolfSSL_i2a_ASN1_INTEGER(bio, asn1Int);

}

int sgx_ASN1_TIME_print(WOLFSSL_BIO_IDENTIFIER bioId, WOLFSSL_ASN1_TIME_IDENTIFIER timeId)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
		return -1;
	WOLFSSL_ASN1_TIME* time = MAP_GET(WolfAsn1TimeMap, timeId);
	if (time == NULL)
		return -1;

	return wolfSSL_ASN1_TIME_print(bio, time);
}


void sgx_ASN1_OBJECT_free(WOLFSSL_ASN1_OBJECT_IDENTIFIER objId)
{
	WOLFSSL_ASN1_OBJECT* obj = MAP_GET(WolfAsn1ObjectMap, objId);
	if (obj == NULL)
		return;

	wolfSSL_ASN1_OBJECT_free(obj);
}


int sgx_OBJ_cmp(WOLFSSL_ASN1_OBJECT_IDENTIFIER objId1, WOLFSSL_ASN1_OBJECT_IDENTIFIER objId2)
{
	WOLFSSL_ASN1_OBJECT* obj1 = MAP_GET(WolfAsn1ObjectMap, objId1);
	WOLFSSL_ASN1_OBJECT* obj2 = MAP_GET(WolfAsn1ObjectMap, objId2);
	if (obj1 == NULL || obj2 == NULL)
		return WOLFSSL_FATAL_ERROR;

	return wolfSSL_OBJ_cmp(obj1, obj2);
}


WOLFSSL_ASN1_OBJECT_IDENTIFIER sgx_OBJ_txt2obj(const char* s, int no_name)
{
	WOLFSSL_ASN1_OBJECT* obj = wolfSSL_OBJ_txt2obj(s, no_name);
	if(obj == NULL)
		return INVALID_IDENTIFIER;
	CheckExistingOrCreate(WOLFSSL_ASN1_OBJECT_IDENTIFIER, objId, obj, WolfAsn1ObjectMap);

	return objId;
}

void sgx_ASN1_STRING_free(WOLFSSL_ASN1_STRING_IDENTIFIER asn1Id)
{
	WOLFSSL_ASN1_STRING* str = MAP_GET(WolfAsn1StringMap, asn1Id);
	if (str == NULL)
	{
		return;
	}
	MAP_REMOVE_TWO_WAY(WolfAsn1StringMap, asn1Id, str);

	wolfSSL_ASN1_STRING_free(str);	
}
