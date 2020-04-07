#include "user_types.h"
#include <wolfssl/ssl.h>
#include "../GenericMap/generic_map.h"


define_map_h(WolfSSLCtxMapType, uint64_t, WOLFSSL_CTX*)
define_map_h(WolfSSLMapType, 	uint64_t, WOLFSSL*)


WOLFSSL_SSL_IDENTIFIER sgx_SSL_new(WOLFSSL_SSL_CTX_IDENTIFIER id);


void initMaps();