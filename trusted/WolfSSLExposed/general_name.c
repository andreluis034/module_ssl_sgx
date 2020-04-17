#include "general_name.h"
#include "maps.h"
#include "../util_defs.h"
#include <wolfssl/openssl/x509v3.h>

#define GET_GENERAL_NAME(var_name, id, default_return_value) WOLFSSL_GENERAL_NAME* var_name = WolfGeneralNameMapTypeGet(&WolfGeneralNameMap, id); if(var_name == NULL) return default_return_value


void internal_GENERAL_NAME_free(WOLFSSL_GENERAL_NAME* name)
{
	WOLFSSL_GENERAL_NAME_IDENTIFIER nameId = WolfGeneralNameMapInverseTypeGet(&WolfGeneralNameMapInverse, name);
	if(nameId != INVALID_IDENTIFIER)
	{
		WolfGeneralNameMapInverseTypeRemove(&WolfGeneralNameMapInverse, name);
		WolfGeneralNameMapTypeRemove(&WolfGeneralNameMap, nameId);
	}
	if (name->type == GEN_EMAIL || name->type == GEN_DNS)
	{
		WOLFSSL_ASN1_INTEGER_IDENTIFIER asn1Id = WolfAsn1StringMapInverseTypeGet(&WolfAsn1StringMapInverse, name->d.ia5);
		if (asn1Id != INVALID_IDENTIFIER)
		{
			WolfAsn1StringMapTypeRemove			(&WolfAsn1StringMap, asn1Id);
			WolfAsn1StringMapInverseTypeRemove	(&WolfAsn1StringMapInverse, name->d.ia5);
		}
	}
	else if(name->type == GEN_OTHERNAME)
	{
		WOLFSSL_ASN1_INTEGER_IDENTIFIER asn1Id = WolfAsn1ObjectMapInverseTypeGet(&WolfAsn1ObjectMapInverse, name->d.otherName->type_id);
		if (asn1Id != INVALID_IDENTIFIER)
		{
			WolfAsn1ObjectMapTypeRemove			(&WolfAsn1ObjectMap, asn1Id);
			WolfAsn1ObjectMapInverseTypeRemove	(&WolfAsn1ObjectMapInverse, name->d.otherName->type_id);
		}
		WOLFSSL_ASN1_TYPE_IDENTIFIER asn1TypeId = WolfAsn1TypeMapInverseTypeGet(&WolfAsn1TypeMapInverse, name->d.otherName->value);
		if (asn1Id != INVALID_IDENTIFIER)
		{
			WolfAsn1TypeMapTypeRemove			(&WolfAsn1TypeMap, asn1Id);
			WolfAsn1TypeMapInverseTypeRemove	(&WolfAsn1TypeMapInverse, name->d.otherName->value);
		}
	}
	
	wolfSSL_GENERAL_NAME_free(name);
}

int sgx_GENERAL_NAME_get_type(WOLFSSL_GENERAL_NAME_IDENTIFIER gnId)
{
	GET_GENERAL_NAME(gn, gnId, -1);

	return gn->type;
}

WOLFSSL_ASN1_STRING_IDENTIFIER sgx_GENERAL_NAME_get_ia5(WOLFSSL_GENERAL_NAME_IDENTIFIER gnId)
{
	GET_GENERAL_NAME(gn, gnId, INVALID_IDENTIFIER);

	WOLFSSL_ASN1_INTEGER_IDENTIFIER asn1Id = WolfAsn1StringMapInverseTypeGet(&WolfAsn1StringMapInverse, gn->d.ia5);
	if (asn1Id == INVALID_IDENTIFIER)
	{
		RandomUntilNonExistant			(asn1Id, WolfAsn1StringMap);
		WolfAsn1StringMapTypeAdd		(&WolfAsn1StringMap, asn1Id, gn->d.ia5);
		WolfAsn1StringMapInverseTypeAdd	(&WolfAsn1StringMapInverse, gn->d.ia5, asn1Id);
	}
	return asn1Id;
}

WOLFSSL_ASN1_OBJECT_IDENTIFIER sgx_GENERAL_NAME_get_othername_type_id(WOLFSSL_GENERAL_NAME_IDENTIFIER gnId)
{
	GET_GENERAL_NAME(gn, gnId, INVALID_IDENTIFIER);
	if (gn->type != GEN_OTHERNAME)
		return INVALID_IDENTIFIER;
	
	WOLFSSL_ASN1_OBJECT_IDENTIFIER asn1Id = WolfAsn1ObjectMapInverseTypeGet(&WolfAsn1ObjectMapInverse, gn->d.otherName->type_id);
	if (asn1Id == INVALID_IDENTIFIER)
	{
		RandomUntilNonExistant			(asn1Id, WolfAsn1ObjectMap);
		WolfAsn1ObjectMapTypeAdd		(&WolfAsn1ObjectMap, asn1Id, gn->d.otherName->type_id);
		WolfAsn1ObjectMapInverseTypeAdd	(&WolfAsn1ObjectMapInverse, gn->d.otherName->type_id, asn1Id);
	}
	return asn1Id;
}

WOLFSSL_ASN1_TYPE_IDENTIFIER   sgx_GENERAL_NAME_get_othername_type_value(WOLFSSL_GENERAL_NAME_IDENTIFIER gnId)
{
	GET_GENERAL_NAME(gn, gnId, INVALID_IDENTIFIER);
	if (gn->type != GEN_OTHERNAME)
		return INVALID_IDENTIFIER;

	WOLFSSL_ASN1_TYPE_IDENTIFIER asn1Id = WolfAsn1TypeMapInverseTypeGet(&WolfAsn1TypeMapInverse, gn->d.otherName->value);
	if (asn1Id == INVALID_IDENTIFIER)
	{
		RandomUntilNonExistant			(asn1Id, WolfAsn1TypeMap);
		WolfAsn1TypeMapTypeAdd			(&WolfAsn1TypeMap, asn1Id, gn->d.otherName->value);
		WolfAsn1TypeMapInverseTypeAdd	(&WolfAsn1TypeMapInverse, gn->d.otherName->value, asn1Id);
	}
	return asn1Id;
}
