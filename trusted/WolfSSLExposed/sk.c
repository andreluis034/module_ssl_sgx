#include "general_name.h"
#include "maps.h"
#include "../util_defs.h"
#define GET_GENERAL_NAME_STACK(var_name, id, default_return_value) WOLFSSL_STACK* var_name =  WolfStackMapTypeGet(&WolfGeneralNameStackMap, id); if(var_name == NULL) return default_return_value


int sgx_sk_GENERAL_NAME_num(WOLFSSL_STACK_IDENTIFIER skId)
{
	WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)* sk = MAP_GET(WolfGeneralNameStackMap, skId);

	return wolfSSL_sk_GENERAL_NAME_num(sk);
}
WOLFSSL_GENERAL_NAME_IDENTIFIER sgx_sk_GENERAL_NAME_value(WOLFSSL_STACK_IDENTIFIER skId, int index)
{
	WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)* sk = MAP_GET(WolfGeneralNameStackMap, skId);

	WOLFSSL_GENERAL_NAME*  name = wolfSSL_sk_GENERAL_NAME_value(sk, index);
	if (name == NULL)
	{
		return INVALID_IDENTIFIER;
	}
	WOLFSSL_GENERAL_NAME_IDENTIFIER nameId = MAP_GET(WolfGeneralNameMapInverse, name);
	if(nameId == INVALID_IDENTIFIER)
	{
		
		RandomUntilNonExistant(nameId, WolfSSLMap);
		WolfGeneralNameMapTypeAdd		(&WolfGeneralNameMap, 			nameId, name);
		WolfGeneralNameMapInverseTypeAdd(&WolfGeneralNameMapInverse, 	name, nameId);
	}

	return nameId;
}


int sgx_sk_GENERAL_NAME_pop_free(WOLFSSL_STACK_IDENTIFIER skId) 
{
	WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)* sk = MAP_GET(WolfGeneralNameStackMap, skId);

	MAP_REMOVE_TWO_WAY(WolfGeneralNameStackMap, skId, sk);

	wolfSSL_sk_GENERAL_NAME_pop_free(sk, internal_GENERAL_NAME_free); //internal_GENERAL_NAME_free will be callsed and clean the maps

}

int sgx_sk_X509_num(WOLFSSL_STACK_IDENTIFIER x509id)
{
	WOLF_STACK_OF(WOLFSSL_X509)* sk = MAP_GET(WolfX509StackMap, x509id);

	return wolfSSL_sk_X509_num(sk);
}

WOLFSSL_X509_IDENTIFIER sgx_sk_X509_value(WOLFSSL_STACK_IDENTIFIER x509id, int index)
{
	WOLF_STACK_OF(WOLFSSL_X509)* sk = MAP_GET(WolfX509StackMap, x509id);

	WOLFSSL_X509* x509 = wolfSSL_sk_X509_value(sk, index);

	CheckExistingOrCreate(WOLFSSL_X509_IDENTIFIER, x509idOut, x509, WolfX509Map);

	return x509idOut;
}