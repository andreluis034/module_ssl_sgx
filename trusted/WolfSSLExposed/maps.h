#include "user_types.h"
#include "../util_defs.h"
#include "../GenericMap/generic_map.h"
#include <wolfssl/ssl.h>
#define define_two_way_maps_h(typeName , keyType, valueType) define_map_h(typeName ## Type, keyType, valueType)\
	define_map_h(typeName ## InverseType , valueType, keyType) \
	extern typeName ## Type typeName;\
	extern typeName ## InverseType typeName ##Inverse;


#define InsertInMap(keyVar, valVar, map) RandomUntilNonExistant(keyVar, map); map ## TypeAdd(&map, keyVar, valVar); map ## InverseTypeAdd(&map ## Inverse, valVar, keyVar);
#define CheckExistingOrCreate(outType, outVar, inVar, map) outType outVar = map ## InverseTypeGet(&map ## Inverse, inVar); if(outVar == INVALID_IDENTIFIER) {InsertInMap(outVar, inVar, map)}
#define MAP_GET(map, key) map ## TypeGet(&map, key);
#define MAP_REMOVE_TWO_WAY(map, key, value) map ## TypeRemove(&map, key); map ## InverseTypeRemove(&map ## Inverse, value);
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


//Asn1
define_two_way_maps_h(WolfAsn1IntergerMap,	WOLFSSL_ASN1_INTEGER_IDENTIFIER, 		WOLFSSL_ASN1_INTEGER*)
define_two_way_maps_h(WolfAsn1StringMap,	WOLFSSL_ASN1_STRING_IDENTIFIER, 		WOLFSSL_ASN1_STRING*)
define_two_way_maps_h(WolfAsn1TypeMap,		WOLFSSL_ASN1_TYPE_IDENTIFIER, 			WOLFSSL_ASN1_TYPE*)
define_two_way_maps_h(WolfAsn1ObjectMap,	WOLFSSL_ASN1_OBJECT_IDENTIFIER, 		WOLFSSL_ASN1_OBJECT*)


//BigNumber
define_two_way_maps_h(WolfBigNumberMap,	WOLFSSL_BIGNUM_IDENTIFIER, 		WOLFSSL_BIGNUM*)


//x509
define_two_way_maps_h(WolfX509Map,			WOLFSSL_X509_IDENTIFIER, 			WOLFSSL_X509*)
define_two_way_maps_h(WolfX509NameEntryMap,	WOLFSSL_X509_NAME_ENTRY_IDENTIFIER, WOLFSSL_X509_NAME_ENTRY*)
define_two_way_maps_h(WolfX509NameMap,		WOLFSSL_X509_NAME_IDENTIFIER, 		WOLFSSL_X509_NAME*)



//Stack
define_two_way_maps_h(WolfStackMap,			WOLFSSL_STACK_IDENTIFIER, 			WOLFSSL_STACK*)

//GeneralName
define_two_way_maps_h(WolfGeneralNameMap,			WOLFSSL_GENERAL_NAME_IDENTIFIER, 			WOLFSSL_GENERAL_NAME*)


