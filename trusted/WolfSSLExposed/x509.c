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
		RandomUntilNonExistant					(stackId, WolfGeneralNameStackMap);
		WolfGeneralNameStackMapTypeAdd(&WolfGeneralNameStackMap, stackId, stack);
		WolfGeneralNameStackMapInverseTypeAdd(&WolfGeneralNameStackMapInverse, stack, stackId);
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

int sgx_X509_cmp_current_time(WOLFSSL_ASN1_TIME_IDENTIFIER timeId)
{
	WOLFSSL_ASN1_TIME* time = MAP_GET(WolfAsn1TimeMap, timeId);
	if(time == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant timeId 0x%X", __func__, timeId);
		return WOLFSSL_FAILURE;
	}
	return wolfSSL_X509_cmp_current_time(time);
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



void sgx_X509_verify_cert_error_string(long err, char* output, int len)
{
	const char* internalStr = wolfSSL_X509_verify_cert_error_string(err);
	strcpy_s(output, len, internalStr);
}

int sgx_X509_up_ref(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	if(x509 == NULL)
		return 0;
	return wolfSSL_X509_up_ref(x509);
}


int sgx_X509_NAME_oneline(WOLFSSL_X509_NAME_IDENTIFIER x509Nameid, char* buffer, size_t buffer_len)
{
	WOLFSSL_X509_NAME* x509Name = MAP_GET(WolfX509NameMap, x509Nameid);
	if(x509Name == NULL)
		return 0;

	wolfSSL_X509_NAME_oneline(x509Name, buffer, buffer_len);
	return 1;
}


int sgx_X509_get_signature_nid(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	if(x509 == NULL)
		return 0;
	
	return wolfSSL_X509_get_signature_nid(x509);
}


int sgx_X509_digest(WOLFSSL_X509_IDENTIFIER x509id, WOLFSSL_EVP_MD_IDENTIFIER digestId, char* buffer, size_t buffer_len)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	WOLFSSL_EVP_MD* digest = MAP_GET(WolfEvpMdMap, digestId);
	if(x509 == NULL || digest == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant x509(%p) or digest(%p)\n", __func__, x509, digest);
		return WOLFSSL_FAILURE;
	}
	int size = (int) buffer_len;
	if(wolfSSL_X509_digest(x509, digest, buffer, &size) == WOLFSSL_SUCCESS)
	{
		return size;
	}
	return WOLFSSL_FAILURE;
}


WOLFSSL_ASN1_STRING_IDENTIFIER sgx_X509_EXTENSION_get_data(WOLFSSL_X509_EXTENSION_IDENTIFIER extId)
{
	WOLFSSL_X509_EXTENSION* ext = MAP_GET(WolfX509ExtensionMap, extId);
	if(ext == NULL)
		return INVALID_IDENTIFIER;
	
	WOLFSSL_ASN1_STRING* str= wolfSSL_X509_EXTENSION_get_data(ext);
	CheckExistingOrCreate(WOLFSSL_ASN1_STRING_IDENTIFIER, strId, str, WolfAsn1StringMap);

	return strId;
}


int sgx_X509V3_EXT_print(WOLFSSL_BIO_IDENTIFIER bioId, WOLFSSL_X509_EXTENSION_IDENTIFIER extId, unsigned long flag, int indent)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	WOLFSSL_X509_EXTENSION* ext = MAP_GET(WolfX509ExtensionMap, extId);
	if(bio == NULL || ext == NULL )
		return WOLFSSL_FAILURE;

	return	wolfSSL_X509V3_EXT_print(bio, ext, flag, indent);
}

WOLFSSL_ASN1_OBJECT_IDENTIFIER sgx_X509_EXTENSION_get_object(WOLFSSL_X509_EXTENSION_IDENTIFIER extId)
{
	WOLFSSL_X509_EXTENSION* ext = MAP_GET(WolfX509ExtensionMap, extId);
	if(ext == NULL )
		return INVALID_IDENTIFIER;
	
	WOLFSSL_ASN1_OBJECT* obj = wolfSSL_X509_EXTENSION_get_object(ext);
	if(obj == NULL)
		return INVALID_IDENTIFIER;
	CheckExistingOrCreate(WOLFSSL_ASN1_OBJECT_IDENTIFIER, objId, obj, WolfAsn1ObjectMap);
	return objId;
}

int sgx_X509_get_ext_count(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	
	if(x509 == NULL)
		return WOLFSSL_FAILURE;

	return wolfSSL_X509_get_ext_count(x509);
}



long sgx_X509_get_version(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	
	if(x509 == NULL)
		return WOLFSSL_FAILURE;

	return wolfSSL_X509_get_version(x509);
}

WOLFSSL_X509_EXTENSION_IDENTIFIER sgx_X509_get_ext(WOLFSSL_X509_IDENTIFIER x509id, int loc)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	
	if(x509 == NULL)
		return INVALID_IDENTIFIER;

	WOLFSSL_X509_EXTENSION* ext = wolfSSL_X509_get_ext(x509, loc);
	if (ext == NULL)
		return INVALID_IDENTIFIER;

	CheckExistingOrCreate(WOLFSSL_X509_EXTENSION_IDENTIFIER, extId, ext, WolfX509ExtensionMap);

	return extId;	 
}

void sgx_X509_ALGOR_get0(WOLFSSL_ASN1_OBJECT_IDENTIFIER* asn1ObjId,  int *pptype, const void**ppval, WOLFSSL_X509_ALGOR_IDENTIFIER algorId)
{
	(void)pptype;
    (void)ppval;
	if (asn1ObjId == NULL)
		return;

	WOLFSSL_X509_ALGOR* algor = MAP_GET(WolfX509AlgoMap, algorId);
	if(algor == NULL)
	{
		*asn1ObjId = INVALID_IDENTIFIER;
		return;
	}
	WOLFSSL_ASN1_OBJECT* asn1Obj;
	wolfSSL_X509_ALGOR_get0((const WOLFSSL_ASN1_OBJECT**)&asn1Obj, NULL, NULL, algor);

	CheckExistingOrCreate(WOLFSSL_ASN1_OBJECT_IDENTIFIER, objId, asn1Obj, WolfAsn1ObjectMap);
	*asn1ObjId = objId;
}

WOLFSSL_X509_ALGOR_IDENTIFIER sgx_X509_get0_tbs_sigalg(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	
	if(x509 == NULL)
		return INVALID_IDENTIFIER;
	
	WOLFSSL_X509_ALGOR* algor = (WOLFSSL_X509_ALGOR*)wolfSSL_X509_get0_tbs_sigalg((const WOLFSSL_X509*)x509);

	CheckExistingOrCreate(WOLFSSL_X509_ALGOR_IDENTIFIER, algId, algor, WolfX509AlgoMap);

	return algId;
}

WOLFSSL_X509_PUBKEY_IDENTIFIER sgx_X509_get_X509_PUBKEY(WOLFSSL_X509_IDENTIFIER x509id)
{
	WOLFSSL_X509* x509 = MAP_GET(WolfX509Map, x509id);
	
	if(x509 == NULL)
		return INVALID_IDENTIFIER;

	WOLFSSL_X509_PUBKEY* key = wolfSSL_X509_get_X509_PUBKEY(x509);

	CheckExistingOrCreate(WOLFSSL_X509_PUBKEY_IDENTIFIER, keyId, key, WolfX509PubKeyMap);

	return keyId;
}

int sgx_X509_PUBKEY_get0_param(WOLFSSL_ASN1_OBJECT_IDENTIFIER* asn1ObjId, const unsigned char **pk, int *ppklen, void **pa, WOLFSSL_X509_PUBKEY_IDENTIFIER pubId)
{
	(void)pk;
    (void)ppklen;
	(void)pa;
	if(asn1ObjId == NULL)
		return WOLFSSL_FAILURE;

	WOLFSSL_X509_PUBKEY* pubKey = MAP_GET(WolfX509PubKeyMap, pubId);
	
	if(pubKey == NULL)
	{
		*asn1ObjId = INVALID_IDENTIFIER;
		return WOLFSSL_FAILURE;
	}
	
	WOLFSSL_ASN1_OBJECT* obj = NULL;
	int result = wolfSSL_X509_PUBKEY_get0_param(&obj, NULL, NULL, NULL, pubKey);

	CheckExistingOrCreate(WOLFSSL_ASN1_OBJECT_IDENTIFIER, objId, obj, WolfAsn1ObjectMap);

	*asn1ObjId = objId;
	return result;
}

int sgx_X509_NAME_entry_count(WOLFSSL_X509_NAME_IDENTIFIER nameId)
{
	WOLFSSL_X509_NAME* name = MAP_GET(WolfX509NameMap, nameId);
	
	if(name == NULL)
		return 0;

	return wolfSSL_X509_NAME_entry_count(name);
}

WOLFSSL_ASN1_OBJECT_IDENTIFIER sgx_X509_NAME_ENTRY_get_object(WOLFSSL_X509_NAME_ENTRY_IDENTIFIER neId)
{
	WOLFSSL_X509_NAME_ENTRY* nameEntry = MAP_GET(WolfX509NameEntryMap, neId);
	if(nameEntry == NULL)
		return INVALID_IDENTIFIER;

	WOLFSSL_ASN1_OBJECT* obj = wolfSSL_X509_NAME_ENTRY_get_object(nameEntry);

	CheckExistingOrCreate(WOLFSSL_ASN1_OBJECT_IDENTIFIER, objId, obj, WolfAsn1ObjectMap);

	return objId;
}
