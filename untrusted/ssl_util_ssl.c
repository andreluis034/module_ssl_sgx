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
 *  ssl_util_ssl.c
 *  Additional Utility Functions for OpenSSL
 */

#include "ssl_private.h"
#include "Enclave_u.h"
extern sgx_enclave_id_t global_eid;    /* global enclave id */

/*  _________________________________________________________________
**
**  Additional High-Level Functions for OpenSSL
**  _________________________________________________________________
*/

/* we initialize this index at startup time
 * and never write to it at request time,
 * so this static is thread safe.
 * also note that OpenSSL increments at static variable when
 * SSL_get_ex_new_index() is called, so we _must_ do this at startup.
 */
static int app_data2_idx = -1;

void modssl_init_app_data2_idx(void)
{
    int i;

    if (app_data2_idx > -1) {
        return;
    }

    /* we _do_ need to call this twice */
    for (i = 0; i <= 1; i++) {
		sgx_SSL_get_ex_new_index(global_eid, &app_data2_idx, 0, "Second Application Data for SSL", strlen("Second Application Data for SSL"));
        //app_data2_idx = SSL_get_ex_new_index(0, "Second Application Data for SSL", NULL, NULL, NULL);
    }
}

void *modssl_get_app_data2(SSL ssl)
{
	void* ret;
	sgx_status_t status = sgx_SSL_get_ex_data(global_eid, &ret, ssl, app_data2_idx);
	if (status == SGX_SUCCESS)
	{
		return  ret;
	}
	
    return NULL;
}

void modssl_set_app_data2(SSL ssl, void *arg)
{
	sgx_SSL_set_app_data(global_eid, ssl, arg);
    return;
}

/*  _________________________________________________________________
**
**  High-Level Private Key Loading
**  _________________________________________________________________
*/

EVP_PKEY modssl_read_privatekey(const char* filename, EVP_PKEY *key, void *passowrdCallback, void *s)
{
    EVP_PKEY rc = INVALID_IDENTIFIER;
    BIO bioS = INVALID_IDENTIFIER;
    BIO bioF = INVALID_IDENTIFIER;
	int freeRetValue;
	sgx_status_t eCallStatus;
    /* 1. try PEM (= DER+Base64+headers) */
	eCallStatus = sgx_BIO_new_file(global_eid, &bioS, filename, "r" );
    if (eCallStatus != SGX_SUCCESS || bioS == INVALID_IDENTIFIER)
        return INVALID_IDENTIFIER;
	
	eCallStatus = sgx_PEM_read_bio_PrivateKey(global_eid, &rc, bioS);//No password callback
    //rc = PEM_read_bio_PrivateKey(bioS, key, passowrdCallback, s);
	
	sgx_BIO_free(global_eid, NULL, bioS);
    //BIO_free(bioS);

    if (rc == INVALID_IDENTIFIER) {
        /* 2. try DER+Base64 */
		eCallStatus = sgx_BIO_new_file(global_eid, &bioS, filename, "r" );
		if (eCallStatus != SGX_SUCCESS || bioS == INVALID_IDENTIFIER)
			return INVALID_IDENTIFIER;

		WOLFSSL_BIO_METHOD_IDENTIFIER method;
		sgx_BIO_f_base64(global_eid, &method);
		eCallStatus = sgx_BIO_new(global_eid, &bioF, method);
        if (eCallStatus != SGX_SUCCESS || bioF == INVALID_IDENTIFIER) {
            sgx_BIO_free(global_eid, NULL, bioS);
            return INVALID_IDENTIFIER;
        }
		
		sgx_BIO_push(global_eid, &bioS, bioF, bioS);
        eCallStatus = sgx_d2i_PrivateKey_bio(global_eid, &rc, bioS);
        
		sgx_BIO_free_all(global_eid, NULL, bioS);

        if (eCallStatus != SGX_SUCCESS  || rc == INVALID_IDENTIFIER)  {
            /* 3. try plain DER */
			eCallStatus = sgx_BIO_new_file(global_eid, &bioS, filename, "r" );
			if (eCallStatus != SGX_SUCCESS || bioS == INVALID_IDENTIFIER)
				return INVALID_IDENTIFIER;

            sgx_d2i_PrivateKey_bio(global_eid, &rc, bioS);
            sgx_BIO_free(global_eid, NULL, bioS);
        }
    }
    if (rc != INVALID_IDENTIFIER && key != INVALID_IDENTIFIER) {
        if (*key != INVALID_IDENTIFIER)
			sgx_EVP_PKEY_free(global_eid, *key);
        *key = rc;
    }
    return rc;
}

typedef struct {
    const char *pass;
    int pass_len;
} pass_ctx;

static int provide_pass(char *buf, int size, int rwflag, void *baton)
{
    pass_ctx *ctx = baton;
    if (ctx->pass_len > 0) {
        if (ctx->pass_len < size) {
            size = (int)ctx->pass_len;
        }
        memcpy(buf, ctx->pass, size);
    }
    return ctx->pass_len;
}

EVP_PKEY   modssl_read_encrypted_pkey(const char *filename, EVP_PKEY *key, const char *pass, apr_size_t pass_len)
{
    pass_ctx ctx;
    
    ctx.pass = pass;
    ctx.pass_len = pass_len;
    return modssl_read_privatekey(filename, key, provide_pass, &ctx);
}

/*  _________________________________________________________________
**
**  Smart shutdown
**  _________________________________________________________________
*/

int modssl_smart_shutdown(SSL ssl)
{
    int i;
    int rc;
    int flush;

    /*
     * Repeat the calls, because SSL_shutdown internally dispatches through a
     * little state machine. Usually only one or two interation should be
     * needed, so we restrict the total number of restrictions in order to
     * avoid process hangs in case the client played bad with the socket
     * connection and OpenSSL cannot recognize it.
     */
    rc = 0;
	sgx_SSL_get_shutdown(global_eid, &flush, ssl);
	flush = !(flush & SSL_SENT_SHUTDOWN);
    for (i = 0; i < 4 /* max 2x pending + 2x data = 4 */; i++) {
		sgx_SSL_shutdown(global_eid, &rc, ssl);
		if(rc >= 0 && flush)
		{
			int is_shutdown;
			sgx_SSL_get_shutdown(global_eid, &is_shutdown, ssl);
			if(is_shutdown & SSL_SENT_SHUTDOWN)
			{
				int flush_result;
				BIO bio;
				sgx_SSL_get_wbio(global_eid, &bio, ssl);
				sgx_BIO_flush(global_eid, &flush_result, bio);
				if(flush_result <= 0 )
				{
					rc = -1;
					break;
				}
				flush = 0;
			}
		}
        if (rc != 0)
            break;
    }
    return rc;
}

/*  _________________________________________________________________
**
**  Certificate Checks
**  _________________________________________________________________
*/

/* retrieve basic constraints ingredients */
BOOL modssl_X509_getBC(X509 cert, int *ca, int *pathlen)
{
	int rc = 0;
    BASIC_CONSTRAINTS bc = INVALID_IDENTIFIER; 
    BIGNUM bn = INVALID_IDENTIFIER;
	WOLFSSL_ASN1_INTEGER_IDENTIFIER pathlenAsn1 = INVALID_IDENTIFIER;
    char *cp;

	sgx_X509_get_ext_d2i(global_eid, &bc, cert, NID_basic_constraints);
    if (bc == INVALID_IDENTIFIER)
        return FALSE;

	sgx_BASIC_CONSTRAINTS_get_ca(global_eid, ca, bc);
	sgx_BASIC_CONSTRAINTS_get_pathlen(global_eid, &pathlenAsn1, bc);

    *pathlen = -1 /* unlimited */;
    if (pathlenAsn1 != INVALID_IDENTIFIER) {
		sgx_ASN1_INTEGER_to_BN(global_eid, &bn, pathlenAsn1);
        if (bn == INVALID_IDENTIFIER) {
            sgx_BASIC_CONSTRAINTS_free(global_eid, bc);
            return FALSE;
        }		
		sgx_BN_to_int(global_eid, &rc, bn, pathlen);
        sgx_BN_free(global_eid, bn);
		if(rc == 0)
		{
			return FALSE;
		}
    }
	sgx_BASIC_CONSTRAINTS_free(global_eid, bc);
    return TRUE;
}

/* Convert ASN.1 string to a pool-allocated char * string, escaping
 * control characters.  If raw is zero, convert to UTF-8, otherwise
 * unchanged from the character set. */
static char *asn1_string_convert(apr_pool_t *p, ASN1_STRING asn1str, int raw)
{
	if (asn1str == INVALID_IDENTIFIER)
		return NULL;
	
    char *result = NULL;
    BIO bio = INVALID_IDENTIFIER;
    int len = 0, flags = ASN1_STRFLGS_ESC_CTRL;
	WOLFSSL_BIO_METHOD_IDENTIFIER mem;
	sgx_BIO_s_mem(global_eid, &mem);
	sgx_BIO_new(global_eid, &bio, mem);
    if (bio == INVALID_IDENTIFIER)
        return NULL;

    if (!raw) flags |= ASN1_STRFLGS_UTF8_CONVERT;
    
    sgx_ASN1_STRING_print_ex(global_eid, NULL, bio, asn1str, flags);
    sgx_BIO_pending(global_eid, &len, bio);
    if (len > 0) {
        result = apr_palloc(p, len+1);
        sgx_BIO_read(global_eid, &len, bio, result, len);
        result[len] = NUL;
    }
	sgx_BIO_free(global_eid, NULL, bio);
    return result;
}

#define asn1_string_to_utf8(p, a) asn1_string_convert(p, a, 0)

/* convert a NAME_ENTRY to UTF8 string */
char *modssl_X509_NAME_ENTRY_to_string(apr_pool_t *p, X509_NAME_ENTRY xsne,
                                       int raw)
{
	ASN1_STRING rc = INVALID_IDENTIFIER;
	sgx_X509_NAME_ENTRY_get_data(global_eid, &rc, xsne);
	if(rc == INVALID_IDENTIFIER)
		return NULL;
    char *result = asn1_string_convert(p, rc, raw);
    ap_xlate_proto_from_ascii(result, len);
    return result;
}

/*
 * convert an X509_NAME to an RFC 2253 formatted string, optionally truncated
 * to maxlen characters (specify a maxlen of 0 for no length limit)
 */
char *modssl_X509_NAME_to_string(apr_pool_t *p, X509_NAME dn, int maxlen)
{
    char *result = NULL;
    BIO bio;
    int len;
    WOLFSSL_BIO_METHOD_IDENTIFIER mem;
	sgx_BIO_s_mem(global_eid, &mem);
	sgx_BIO_new(global_eid, &bio, mem);
    if (bio == INVALID_IDENTIFIER)
        return NULL;
    sgx_X509_NAME_print_ex(global_eid, NULL, bio, dn, 0, XN_FLAG_RFC2253);
    sgx_BIO_pending(global_eid, &len, bio);
    if (len > 0) {
        result = apr_palloc(p, (maxlen > 0) ? maxlen+1 : len+1);
        if (maxlen > 0 && maxlen < len) {
            sgx_BIO_read(global_eid, NULL, bio, result, maxlen);
            if (maxlen > 2) {
                /* insert trailing ellipsis if there's enough space */
                apr_snprintf(result + maxlen - 3, 4, "...");
            }
        } else {
            sgx_BIO_read(global_eid, NULL, bio, result, len);
        }
        result[len] = NUL;
    }
	sgx_BIO_free(global_eid, NULL, bio);

    return result;
}

static void parse_otherName_value(apr_pool_t *p, ASN1_TYPE value,
                                  const char *onf, apr_array_header_t **entries)
{
    const char *str;
    int nid = NID_undef;
    int type;
    ASN1_STRING asn1Str;
    if (onf)
    {
        sgx_OBJ_txt2nid(global_eid, &nid, onf);
    }
    
    if (!value || (nid == NID_undef) || !*entries)
       return;


    sgx_ASN1_TYPE_get_type(global_eid, &type, value);
    sgx_ASN1_TYPE_get_string(global_eid, &asn1Str, value);
    /* 
     * Currently supported otherName forms (values for "onf"):
     * "msUPN" (1.3.6.1.4.1.311.20.2.3): Microsoft User Principal Name
     * "id-on-dnsSRV" (1.3.6.1.5.5.7.8.7): SRVName, as specified in RFC 4985
     */
    if ((nid == NID_ms_upn) && (type == V_ASN1_UTF8STRING) &&
        (str = asn1_string_to_utf8(p, asn1Str))) {
        APR_ARRAY_PUSH(*entries, const char *) = str;
    } else if (strEQ(onf, "id-on-dnsSRV") &&
               (type == V_ASN1_IA5STRING) &&
               (str = asn1_string_to_utf8(p, asn1Str))) {
        APR_ARRAY_PUSH(*entries, const char *) = str;
    }
}

/* 
 * Return an array of subjectAltName entries of type "type". If idx is -1,
 * return all entries of the given type, otherwise return an array consisting
 * of the n-th occurrence of that type only. Currently supported types:
 * GEN_EMAIL (rfc822Name)
 * GEN_DNS (dNSName)
 * GEN_OTHERNAME (requires the otherName form ["onf"] argument to be supplied,
 *                see parse_otherName_value for the currently supported forms)
 */
BOOL modssl_X509_getSAN(apr_pool_t *p, X509 x509, int type, const char *onf,
                        int idx, apr_array_header_t **entries)
{
    //STACK_OF(GENERAL_NAME) *names;
	SSL_STACK names;
    int nid = NID_undef;
    if (onf)
    {
        sgx_OBJ_txt2nid(global_eid, &nid, onf);
    }

    if (!x509 || (type < GEN_OTHERNAME) ||
        ((type == GEN_OTHERNAME) && (nid == NID_undef)) ||
        (type > GEN_RID) || (idx < -1) ||
        !(*entries = apr_array_make(p, 0, sizeof(char *)))) {
        *entries = NULL;
        return FALSE;
    }

    sgx_X509_get_ext_d2i(global_eid, &names, x509, NID_subject_alt_name);
    if (names != INVALID_IDENTIFIER) {
        int i, n = 0;
        GENERAL_NAME name;
        const char *utf8str;
		int nameCount = 0;
		int gnType;
		int otherNid;
		ASN1_STRING asn1Str = INVALID_IDENTIFIER;
		ASN1_OBJECT asn1Obj = INVALID_IDENTIFIER;
		ASN1_TYPE 	asn1Typ = INVALID_IDENTIFIER;
		sgx_sk_GENERAL_NAME_num(global_eid, &nameCount, names);
        for (i = 0; i < nameCount; i++) {
			sgx_sk_GENERAL_NAME_value(global_eid, &name, names, i);
			if(name == INVALID_IDENTIFIER)
				continue;
			sgx_GENERAL_NAME_get_type(global_eid, &gnType, name);
            if (gnType != type)
                continue;

            switch (type) {
            case GEN_EMAIL:
            case GEN_DNS:
				sgx_GENERAL_NAME_get_ia5(global_eid, &asn1Str, name);
                if (((idx == -1) || (n == idx)) &&
                    (utf8str = asn1_string_to_utf8(p, asn1Str))) 
				{
                    APR_ARRAY_PUSH(*entries, const char *) = utf8str;
                }
                n++;
                break;
            case GEN_OTHERNAME:
				sgx_GENERAL_NAME_get_othername_type_id(global_eid, &asn1Obj, name);
				if (asn1Obj == INVALID_IDENTIFIER)
					continue;
				sgx_OBJ_obj2nid(global_eid, &otherNid, name);
				

                if (otherNid == nid) {
                    if (((idx == -1) || (n == idx))) {
						sgx_GENERAL_NAME_get_othername_type_value(global_eid, &asn1Typ, name);
                        parse_otherName_value(p, asn1Typ,onf, entries);
                    }
                    n++;
                }
                break;
            default:
                /*
                 * Not implemented right now:
                 * GEN_X400 (x400Address)
                 * GEN_DIRNAME (directoryName)
                 * GEN_EDIPARTY (ediPartyName)
                 * GEN_URI (uniformResourceIdentifier)
                 * GEN_IPADD (iPAddress)
                 * GEN_RID (registeredID)
                 */
                break;
            }

            if ((idx != -1) && (n > idx))
               break;
        }

        sgx_sk_GENERAL_NAME_pop_free(global_eid, NULL, names);
    }

    return apr_is_empty_array(*entries) ? FALSE : TRUE;
}

/* return an array of (RFC 6125 coined) DNS-IDs and CN-IDs in a certificate */
static BOOL getIDs(apr_pool_t *p, X509 x509, apr_array_header_t **ids)
{
    X509_NAME subj;
	X509_NAME_ENTRY entry;
    int i = -1;

    /* First, the DNS-IDs (dNSName entries in the subjectAltName extension) */
    if (!x509 ||
        (modssl_X509_getSAN(p, x509, GEN_DNS, NULL, -1, ids) == FALSE && !*ids)) {
        *ids = NULL;
        return FALSE;
    }

    /* Second, the CN-IDs (commonName attributes in the subject DN) */
	sgx_X509_get_subject_name(global_eid, &subj, x509);

    while (sgx_X509_NAME_get_index_by_NID(global_eid, &i, subj, NID_commonName, i) == SGX_SUCCESS &&  i != -1) {
		sgx_X509_NAME_get_entry(global_eid, &entry, subj, i);
        APR_ARRAY_PUSH(*ids, const char *) = 
            modssl_X509_NAME_ENTRY_to_string(p, entry, 0);
			sgx_X509_NAME_ENTRY_remove_from_map(global_eid, entry);
    }

    return apr_is_empty_array(*ids) ? FALSE : TRUE;
}

/* 
 * Check if a certificate matches for a particular name, by iterating over its
 * DNS-IDs and CN-IDs (RFC 6125), optionally with basic wildcard matching.
 * If server_rec is non-NULL, some (debug/trace) logging is enabled.
 */
BOOL modssl_X509_match_name(apr_pool_t *p, X509 x509, const char *name,
                            BOOL allow_wildcard, server_rec *s)
{
    BOOL matched = FALSE;
    apr_array_header_t *ids;

    /*
     * At some day in the future, this might be replaced with X509_check_host()
     * (available in OpenSSL 1.0.2 and later), but two points should be noted:
     * 1) wildcard matching in X509_check_host() might yield different
     *    results (by default, it supports a broader set of patterns, e.g.
     *    wildcards in non-initial positions);
     * 2) we lose the option of logging each DNS- and CN-ID (until a match
     *    is found).
     */

    if (getIDs(p, x509, &ids)) {
        const char *cp;
        int i;
        char **id = (char **)ids->elts;
        BOOL is_wildcard;

        for (i = 0; i < ids->nelts; i++) {
            if (!id[i])
                continue;

            /*
             * Determine if it is a wildcard ID - we're restrictive
             * in the sense that we require the wildcard character to be
             * THE left-most label (i.e., the ID must start with "*.")
             */
            is_wildcard = (*id[i] == '*' && *(id[i]+1) == '.') ? TRUE : FALSE;

            /*
             * If the ID includes a wildcard character (and the caller is
             * allowing wildcards), check if it matches for the left-most
             * DNS label - i.e., the wildcard character is not allowed
             * to match a dot. Otherwise, try a simple string compare.
             */
            if ((allow_wildcard == TRUE && is_wildcard == TRUE &&
                 (cp = ap_strchr_c(name, '.')) && !strcasecmp(id[i]+1, cp)) ||
                !strcasecmp(id[i], name)) {
                matched = TRUE;
            }

            if (s) {
                ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
                             "[%s] modssl_X509_match_name: expecting name '%s', "
                             "%smatched by ID '%s'",
                             (mySrvConfig(s))->vhost_id, name,
                             matched == TRUE ? "" : "NOT ", id[i]);
            }

            if (matched == TRUE) {
                break;
            }
        }

    }

    if (s) {
        ssl_log_xerror(SSLLOG_MARK, APLOG_DEBUG, 0, p, s, x509,
                       APLOGNO(02412) "[%s] Cert %s for name '%s'",
                       (mySrvConfig(s))->vhost_id,
                       matched == TRUE ? "matches" : "does not match",
                       name);
    }

    return matched;
}

/*  _________________________________________________________________
**
**  Custom (EC)DH parameter support
**  _________________________________________________________________
*/

DH ssl_dh_GetParamFromFile(const char *file)
{
    DH dh = INVALID_IDENTIFIER;
    BIO bio;
    sgx_BIO_new_file(global_eid, &bio, file, "r");
    if (bio == INVALID_IDENTIFIER)
        return INVALID_IDENTIFIER;
    sgx_PEM_read_bio_DHparams(global_eid, &dh, bio);
    sgx_BIO_free(global_eid, NULL, bio);
    return (dh);
}

#ifdef HAVE_ECC
EC_GROUP ssl_ec_GetParamFromFile(const char *file)
{
    EC_GROUP *group = NULL;
    BIO *bio;

    if ((bio = BIO_new_file(file, "r")) == NULL)
        return NULL;
    group = PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return (group);
}
#endif

/*  _________________________________________________________________
**
**  Session Stuff
**  _________________________________________________________________
*/

char *modssl_SSL_SESSION_id2sz(IDCONST unsigned char *id, int idlen,
                               char *str, int strsize)
{
    if (idlen > _SSL_MAX_SSL_SESSION_ID_LENGTH)
        idlen = _SSL_MAX_SSL_SESSION_ID_LENGTH;
        
    /* We must ensure not to process more than what would fit in the
     * destination buffer, including terminating NULL */
    if (idlen > (strsize-1) / 2)
        idlen = (strsize-1) / 2;

    ap_bin2hex(id, idlen, str);

    return str;
}
