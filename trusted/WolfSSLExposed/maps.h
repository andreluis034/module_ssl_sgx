#include "user_types.h"
#include "../GenericMap/generic_map.h"
#include <wolfssl/ssl.h>
#define define_two_way_maps_h(typeName , keyType, valueType) define_map_h(typeName ## Type, keyType, valueType)\
	define_map_h(typeName ## InverseType , valueType, keyType) \
	extern typeName ## Type typeName;\
	extern typeName ## InverseType typeName ##Inverse;




//SSL
define_two_way_maps_h(WolfSSLCtxMap, WOLFSSL_SSL_CTX_IDENTIFIER, WOLFSSL_CTX*)
define_two_way_maps_h(WolfSSLMap, 	WOLFSSL_SSL_IDENTIFIER, 	WOLFSSL*)

//BIO
define_two_way_maps_h(WolfBioMap,		WOLFSSL_BIO_IDENTIFIER, 		WOLFSSL_BIO*)

//DH
define_two_way_maps_h(WolfDhMap,		WOLFSSL_DH_IDENTIFIER, 		WOLFSSL_DH*)

//EVP_PKEY
define_two_way_maps_h(WolfEvpPkeyMap,	WOLFSSL_EVP_PKEY_IDENTIFIER, 		WOLFSSL_EVP_PKEY*)


//BASIC_CONSTRAINTS
define_two_way_maps_h(WolfBasicConstraintsMap,	WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER, 		WOLFSSL_BASIC_CONSTRAINTS*)


//Asn1 - TODO FIX TO ASN 1 Int
define_two_way_maps_h(WolfAsn1Map,	WOLFSSL_ASN1_INTEGER_IDENTIFIER, 		WOLFSSL_ASN1_INTEGER*)


//BigNumber
define_two_way_maps_h(WolfBigNumberMap,	WOLFSSL_BIGNUM_IDENTIFIER, 		WOLFSSL_BIGNUM*)


//x509
define_two_way_maps_h(WolfX509Map,	WOLFSSL_X509_IDENTIFIER, 		WOLFSSL_X509*)
define_two_way_maps_h(WolfX509NameEntryMap,	WOLFSSL_X509_NAME_ENTRY_IDENTIFIER, 		WOLFSSL_X509_NAME_ENTRY*)



