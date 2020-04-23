/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_scache.c
 *  Session Cache Abstraction
 */
                             /* ``Open-Source Software: generous
                                  programmers from around the world all
                                  join forces to help you shoot
                                  yourself in the foot for free.''
                                                 -- Unknown         */
#include "ssl_private.h"
#include "mod_status.h"
#include "Enclave_u.h"
extern sgx_enclave_id_t global_eid;    /* global enclave id */
/*  _________________________________________________________________
**
**  Session Cache: Common Abstraction Layer
**  _________________________________________________________________
*/

apr_status_t ssl_scache_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;
    struct ap_socache_hints hints;

    /* The very first invocation of this function will be the
     * post_config invocation during server startup; do nothing for
     * this first (and only the first) time through, since the pool
     * will be immediately cleared anyway.  For every subsequent
     * invocation, initialize the configured cache. */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
        return APR_SUCCESS;

#ifdef HAVE_OCSP_STAPLING
    if (mc->stapling_cache) {
        memset(&hints, 0, sizeof hints);
        hints.avg_obj_size = 1500;
        hints.avg_id_len = 20;
        hints.expiry_interval = 300;

        rv = mc->stapling_cache->init(mc->stapling_cache_context,
                                     "mod_ssl-stapling", &hints, s, p);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01872)
                         "Could not initialize stapling cache. Exiting.");
            return ssl_die(s);
        }
    }
#endif

    /*
     * Warn the user that he should use the session cache.
     * But we can operate without it, of course.
     */
    if (mc->sesscache == NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(01873)
                     "Init: Session Cache is not configured "
                     "[hint: SSLSessionCache]");
        return APR_SUCCESS;
    }

    memset(&hints, 0, sizeof hints);
    hints.avg_obj_size = 150;
    hints.avg_id_len = 30;
    hints.expiry_interval = 30;

    rv = mc->sesscache->init(mc->sesscache_context, "mod_ssl-session", &hints, s, p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01874)
                     "Could not initialize session cache. Exiting.");
        return ssl_die(s);
    }

    return APR_SUCCESS;
}

void ssl_scache_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->sesscache) {
        mc->sesscache->destroy(mc->sesscache_context, s);
    }

#ifdef HAVE_OCSP_STAPLING
    if (mc->stapling_cache) {
        mc->stapling_cache->destroy(mc->stapling_cache_context, s);
    }
#endif

}

BOOL ssl_scache_store(server_rec *s, IDCONST UCHAR *id, int idlen,
                      apr_time_t expiry, SSL_SESSION sess,
                      apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    unsigned char encoded[MODSSL_SESSION_MAX_DER], *ptr;
    unsigned int len;
    apr_status_t rv;

    /* Serialise the session. */
	sgx_status_t sgx_status = sgx_i2d_SSL_SESSION(global_eid, &len, sess, NULL, 0);

	if(sgx_status != SGX_SUCCESS)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01875)
                     "sgx ERROR sgx_i2d_SSL_SESSION did not return successfully. Error: 0x%x", sgx_status);
        return FALSE;
	}
	if(len <= 0)	{
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01875)
                     "Invalid session passed to i2d_SSL_SESSION");
        return FALSE;
	}
    if (len > sizeof encoded) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01875)
                     "session is too big (%u bytes)", len);
        return FALSE;
    }
	

    ptr = encoded;
	sgx_status = sgx_i2d_SSL_SESSION(global_eid, &len, sess, encoded, MODSSL_SESSION_MAX_DER);
	if(sgx_status != SGX_SUCCESS)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01875)
                     "sgx ERROR sgx_i2d_SSL_SESSION failed to serialize Error: 0x%x", sgx_status);
        return FALSE;
	}
    if (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        ssl_mutex_on(s);
    }

    rv = mc->sesscache->store(mc->sesscache_context, s, id, idlen,
                              expiry, encoded, len, p);

    if (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        ssl_mutex_off(s);
    }

    return rv == APR_SUCCESS ? TRUE : FALSE;
}

SSL_SESSION ssl_scache_retrieve(server_rec *s, IDCONST UCHAR *id, int idlen,
                                 apr_pool_t *p)
{
	SSL_SESSION ret;
    SSLModConfigRec *mc = myModConfig(s);
    unsigned char dest[MODSSL_SESSION_MAX_DER];
    unsigned int destlen = sizeof(dest);
    const unsigned char *ptr;
    apr_status_t rv;

    if (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        ssl_mutex_on(s);
    }

    rv = mc->sesscache->retrieve(mc->sesscache_context, s, id, idlen,
                                 dest, &destlen, p);

    if (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        ssl_mutex_off(s);
    }

    if (rv != APR_SUCCESS) {
        return INVALID_IDENTIFIER;
    }

    ptr = dest;

	sgx_status_t error = sgx_d2i_SSL_SESSION(global_eid, &ret, NULL, dest, destlen);
	if (error == SGX_SUCCESS)
	{
		return ret;
	}
	
    return INVALID_IDENTIFIER;
}

void ssl_scache_remove(server_rec *s, IDCONST UCHAR *id, int idlen,
                       apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        ssl_mutex_on(s);
    }

    mc->sesscache->remove(mc->sesscache_context, s, id, idlen, p);

    if (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        ssl_mutex_off(s);
    }
}

/*  _________________________________________________________________
**
**  SSL Extension to mod_status
**  _________________________________________________________________
*/
static int ssl_ext_status_hook(request_rec *r, int flags)
{
    SSLModConfigRec *mc = myModConfig(r->server);

    if (mc == NULL || mc->sesscache == NULL)
        return OK;

    if (!(flags & AP_STATUS_SHORT)) {
        ap_rputs("<hr>\n", r);
        ap_rputs("<table cellspacing=0 cellpadding=0>\n", r);
        ap_rputs("<tr><td bgcolor=\"#000000\">\n", r);
        ap_rputs("<b><font color=\"#ffffff\" face=\"Arial,Helvetica\">SSL/TLS Session Cache Status:</font></b>\r", r);
        ap_rputs("</td></tr>\n", r);
        ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);
    }
    else {
        ap_rputs("TLSSessionCacheStatus\n", r);
    }

    if (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        ssl_mutex_on(r->server);
    }

    mc->sesscache->status(mc->sesscache_context, r, flags);

    if (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        ssl_mutex_off(r->server);
    }

    if (!(flags & AP_STATUS_SHORT)) {
        ap_rputs("</td></tr>\n", r);
        ap_rputs("</table>\n", r);
    }

    return OK;
}

void ssl_scache_status_register(apr_pool_t *p)
{
    APR_OPTIONAL_HOOK(ap, status_hook, ssl_ext_status_hook, NULL, NULL,
                      APR_HOOK_MIDDLE);
}

