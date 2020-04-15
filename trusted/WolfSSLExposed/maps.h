#include "user_types.h"
#include "../GenericMap/generic_map.h"
#include <wolfssl/ssl.h>
#define define_two_way_maps_h(typeName , keyType, valueType) define_map_h(typeName ## Type, keyType, valueType)\
	define_map_h(typeName ## InverseType , valueType, keyType)



//SSL
define_two_way_maps_h(WolfSSLCtxMap, WOLFSSL_SSL_CTX_IDENTIFIER, WOLFSSL_CTX*)
define_two_way_maps_h(WolfSSLMap, 	WOLFSSL_SSL_IDENTIFIER, 	WOLFSSL*)

extern WolfSSLCtxMapType 	WolfSSLCtxMap;
extern WolfSSLMapType 		WolfSSLMap;

extern WolfSSLCtxMapInverseType 	WolfSSLCtxMapInverse;
extern WolfSSLMapInverseType 		WolfSSLMapInverse;

//BIO
define_two_way_maps_h(WolfBioMap,		WOLFSSL_BIO_IDENTIFIER, 		WOLFSSL_BIO*)

extern WolfBioMapType 			WolfBioMap;
extern WolfBioMapInverseType 	WolfBioMapInverse;

//DH
define_two_way_maps_h(WolfDhMap,		WOLFSSL_DH_IDENTIFIER, 		WOLFSSL_DH*)

extern WolfDhMapType 			WolfDhMap;
extern WolfDhMapInverseType 	WolfDhMapInverse;

//EVP_PKEY
define_two_way_maps_h(WolfEvpPkeyMap,	WOLFSSL_EVP_PKEY_IDENTIFIER, 		WOLFSSL_EVP_PKEY*)

extern WolfEvpPkeyMapType 			WolfEvpPkeyMap;
extern WolfEvpPkeyMapInverseType 	WolfEvpPkeyMapInverse;

