#include "maps.h"
#include "../util_defs.h"

#define GET_BC_NO_RET_VAL(var_name, id) WOLFSSL_BASIC_CONSTRAINTS* var_name =  WolfBasicConstraintsMapTypeGet(&WolfBasicConstraintsMap, id); if(var_name == NULL) return
#define GET_BC(var_name, id, default_return_value) GET_BC_NO_RET_VAL(var_name, id) default_return_value


void sgx_BASIC_CONSTRAINTS_free(WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER bcId)
{
	GET_BC_NO_RET_VAL(bc, bcId);

	WolfBasicConstraintsMapTypeRemove(&WolfBasicConstraintsMap, bcId);
	WolfBasicConstraintsMapInverseTypeRemove(&WolfBasicConstraintsMapInverse, bc);
	//TODO ALSO FREE pathlen
	wolfSSL_BASIC_CONSTRAINTS_free(bc);
}


int sgx_BASIC_CONSTRAINTS_get_ca(WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER bcId)
{
	GET_BC(bc, bcId, -1);
	
	return bc->ca;
}


WOLFSSL_ASN1_INTEGER_IDENTIFIER sgx_BASIC_CONSTRAINTS_get_pathlen(WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER bcId)
{
	GET_BC(bc, bcId, -1);
	
	WOLFSSL_ASN1_INTEGER* pathlen = bc->pathlen;
	if (pathlen == NULL)
		return INVALID_IDENTIFIER;
	
	WOLFSSL_ASN1_INTEGER_IDENTIFIER pathlenId =  WolfAsn1IntergerMapInverseTypeGet(&WolfAsn1IntergerMapInverse, pathlen);
	if (pathlenId)
	{
		RandomUntilNonExistant	(pathlenId, WolfAsn1IntergerMap);
		WolfAsn1IntergerMapTypeAdd		(&WolfAsn1IntergerMap, pathlenId, pathlen);
		WolfAsn1IntergerMapInverseTypeAdd(&WolfAsn1IntergerMapInverse, pathlen, pathlenId);
		return pathlenId;
	}
	
	return pathlenId;
}
