
#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif



#define ENCLAVE_FILENAME "Enclave.signed.so"


extern sgx_enclave_id_t global_eid;    /* global enclave id */
extern module AP_MODULE_DECLARE_DATA   ssl_module;
#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif


/** The ssl_var_lookup() optional function retrieves SSL environment
 * variables. */
APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *,
                         char *));

/** The ssl_ext_list() optional function attempts to build an array
 * of all the values contained in the named X.509 extension. The
 * returned array will be created in the supplied pool.
 * The client certificate is used if peer is non-zero; the server
 * certificate is used otherwise.
 * Extension specifies the extensions to use as a string. This can be
 * one of the "known" long or short names, or a numeric OID,
 * e.g. "1.2.3.4", 'nsComment' and 'DN' are all valid.
 * A pointer to an apr_array_header_t structure is returned if at
 * least one matching extension is found, NULL otherwise.
 */
APR_DECLARE_OPTIONAL_FN(apr_array_header_t *, ssl_ext_list,
                        (apr_pool_t *p, conn_rec *c, int peer,
                         const char *extension));

/** An optional function which returns non-zero if the given connection
 * is using SSL/TLS. */
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

/** A function that returns the TLS channel binding data as per
 * RFC5929.  A buffer containing the Channel Binding Token for the
 * given type will be allocated from the pool and returned to the
 * caller, along with the size.  Returns APR_SUCCESS on success; buf
 * and size are not adjusted on error. */
APR_DECLARE_OPTIONAL_FN(apr_status_t, ssl_get_tls_cb,
                        (apr_pool_t *p, conn_rec *c, const char *type,
                         unsigned char **buf, apr_size_t *size));

/** The ssl_proxy_enable() and ssl_engine_{set,disable}() optional
 * functions are used by mod_proxy to enable use of SSL for outgoing
 * connections. */

APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_set, (conn_rec *,
                                              ap_conf_vector_t *,
                                              int proxy, int enable));


#endif /* !_APP_H_ */
