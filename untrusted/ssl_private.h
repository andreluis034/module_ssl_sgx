#pragma once
#include "user_types.h"
#include <ap_socache.h>
#ifndef BOOL
#define BOOL unsigned char
#endif
#ifndef UNSET
#define UNSET (-1)
#endif
/**
 * Defs 
 * 
 */
#define myConnConfig(c) \
    ((SSLConnRec *)ap_get_module_config(c->conn_config, &ssl_module))
#define mySrvConfig(srv) \
    ((SSLSrvConfigRec *)ap_get_module_config(srv->module_config,  &ssl_module))
#define myConnConfigSet(c, val) \
    ap_set_module_config(c->conn_config, &ssl_module, val)



/**
 * Define the SSL options
 */
#define SSL_OPT_NONE           (0)
#define SSL_OPT_RELSET         (1<<0)
#define SSL_OPT_STDENVVARS     (1<<1)
#define SSL_OPT_EXPORTCERTDATA (1<<3)
#define SSL_OPT_FAKEBASICAUTH  (1<<4)
#define SSL_OPT_STRICTREQUIRE  (1<<5)
#define SSL_OPT_OPTRENEGOTIATE (1<<6)
#define SSL_OPT_LEGACYDNFORMAT (1<<7)
typedef int ssl_opt_t;

/**
 * Define the SSL Protocol options
 */
#define SSL_PROTOCOL_NONE  (0)
#ifndef OPENSSL_NO_SSL3
#define SSL_PROTOCOL_SSLV3 (1<<1)
#endif
#define SSL_PROTOCOL_TLSV1 (1<<2)
#ifndef OPENSSL_NO_SSL3
#define SSL_PROTOCOL_BASIC (SSL_PROTOCOL_SSLV3|SSL_PROTOCOL_TLSV1)
#else
#define SSL_PROTOCOL_BASIC (SSL_PROTOCOL_TLSV1)
#endif
#ifdef HAVE_TLSV1_X
#define SSL_PROTOCOL_TLSV1_1 (1<<3)
#define SSL_PROTOCOL_TLSV1_2 (1<<4)
#define SSL_PROTOCOL_TLSV1_3 (1<<5)

#ifdef SSL_OP_NO_TLSv1_3
#define SSL_HAVE_PROTOCOL_TLSV1_3   (1)
#define SSL_PROTOCOL_ALL   (SSL_PROTOCOL_BASIC| \
                            SSL_PROTOCOL_TLSV1_1|SSL_PROTOCOL_TLSV1_2|SSL_PROTOCOL_TLSV1_3)
#else
#define SSL_HAVE_PROTOCOL_TLSV1_3   (0)
#define SSL_PROTOCOL_ALL   (SSL_PROTOCOL_BASIC| \
                            SSL_PROTOCOL_TLSV1_1|SSL_PROTOCOL_TLSV1_2)
#endif
#else
#define SSL_PROTOCOL_ALL   (SSL_PROTOCOL_BASIC)
#endif
#ifndef OPENSSL_NO_SSL3
#define SSL_PROTOCOL_DEFAULT (SSL_PROTOCOL_ALL & ~SSL_PROTOCOL_SSLV3)
#else
#define SSL_PROTOCOL_DEFAULT (SSL_PROTOCOL_ALL)
#endif
typedef int ssl_proto_t;

typedef struct SSLSrvConfigRec SSLSrvConfigRec;
typedef struct SSLDirConfigRec SSLDirConfigRec;



typedef enum {
    SSL_SHUTDOWN_TYPE_UNSET,
    SSL_SHUTDOWN_TYPE_STANDARD,
    SSL_SHUTDOWN_TYPE_UNCLEAN,
    SSL_SHUTDOWN_TYPE_ACCURATE
} ssl_shutdown_type_e;

typedef enum {
    SSL_ENABLED_UNSET    = UNSET,
    SSL_ENABLED_FALSE    = 0,
    SSL_ENABLED_TRUE     = 1,
    SSL_ENABLED_OPTIONAL = 3
} ssl_enabled_t;


typedef struct {
    /* Lists of configured certs and keys for this server */
    apr_array_header_t *cert_files;
    apr_array_header_t *key_files;

    /** Certificates which specify the set of CA names which should be
     * sent in the CertificateRequest message: */
    const char  *ca_name_path;
    const char  *ca_name_file;
    
    /* TLS service for this server is suspended */
    int service_unavailable;
} modssl_pk_server_t;


typedef struct {
    /** proxy can have any number of cert/key pairs */
    const char  *cert_file;
    const char  *cert_path;
    const char  *ca_cert_file;
  //  STACK_OF(X509_INFO) *certs; /* Contains End Entity certs */
 /* STACK_OF(X509) **ca_certs; /* Contains ONLY chain certs for
                                * each item in certs.
                                * (ptr to array of ptrs) */
} modssl_pk_proxy_t;


/**
 * Define the SSL pass phrase dialog types
 */
typedef enum {
    SSL_PPTYPE_UNSET   = UNSET,
    SSL_PPTYPE_BUILTIN = 0,
    SSL_PPTYPE_FILTER  = 1,
    SSL_PPTYPE_PIPE    = 2
} ssl_pphrase_t;


typedef enum {
    SSL_CVERIFY_UNSET           = UNSET,
    SSL_CVERIFY_NONE            = 0,
    SSL_CVERIFY_OPTIONAL        = 1,
    SSL_CVERIFY_REQUIRE         = 2,
    SSL_CVERIFY_OPTIONAL_NO_CA  = 3
} ssl_verify_t;

/** stuff related to authentication that can also be per-dir */
typedef struct {
    /** known/trusted CAs */
    const char  *ca_cert_path;
    const char  *ca_cert_file;

    const char  *cipher_suite;

    /** for client or downstream server authentication */
    int          verify_depth;
    ssl_verify_t verify_mode;

    /** TLSv1.3 has its separate cipher list, separate from the
     settings for older TLS protocol versions. Since which one takes
     effect is a matter of negotiation, we need separate settings */
    const char  *tls13_ciphers;
} modssl_auth_ctx_t;


typedef struct {
    SSLSrvConfigRec *sc; /** pointer back to server config */
    WOLFSSL_SSL_CTX_IDENTIFIER *ssl_ctx;

    /** we are one or the other */
    modssl_pk_server_t *pks;
    modssl_pk_proxy_t  *pkp;

#ifdef HAVE_TLS_SESSION_TICKETS
    modssl_ticket_key_t *ticket_key;
#endif

    ssl_proto_t  protocol;
    int protocol_set;

    /** config for handling encrypted keys */
    ssl_pphrase_t pphrase_dialog_type;
    const char   *pphrase_dialog_path;

    const char  *cert_chain;

    /** certificate revocation list */
    const char    *crl_path;
    const char    *crl_file;
    int            crl_check_mask;


    modssl_auth_ctx_t auth;

    int ocsp_mask;
    BOOL ocsp_force_default; /* true if the default responder URL is
                              * used regardless of per-cert URL */
    const char *ocsp_responder; /* default responder URL */
    long ocsp_resptime_skew;
    long ocsp_resp_maxage;
    apr_interval_time_t ocsp_responder_timeout;
    BOOL ocsp_use_request_nonce;
    apr_uri_t *proxy_uri;

    BOOL ocsp_noverify; /* true if skipping OCSP certification verification like openssl -noverify */
    /* Declare variables for using OCSP Responder Certs for OCSP verification */
    int ocsp_verify_flags; /* Flags to use when verifying OCSP response */
    const char *ocsp_certs_file; /* OCSP other certificates filename */
  //  STACK_OF(X509) *ocsp_certs; /* OCSP other certificates */

#ifdef HAVE_SSL_CONF_CMD
    SSL_CONF_CTX *ssl_ctx_config; /* Configuration context */
    apr_array_header_t *ssl_ctx_param; /* parameters to pass to SSL_CTX */
#endif

    BOOL ssl_check_peer_cn;
    BOOL ssl_check_peer_name;
    BOOL ssl_check_peer_expire;
} modssl_ctx_t;

typedef struct {
    WOLFSSL_SSL_IDENTIFIER ssl;
    const char *client_dn;
    WOLFSSL_X509_IDENTIFIER client_cert;
    ssl_shutdown_type_e shutdown_type;
    const char *verify_info;
    const char *verify_error;
    int verify_depth;
    int is_proxy;
    int disabled;
    enum {
        NON_SSL_OK = 0,        /* is SSL request, or error handling completed */
        NON_SSL_SEND_REQLINE,  /* Need to send the fake request line */
        NON_SSL_SEND_HDR_SEP,  /* Need to send the header separator */
        NON_SSL_SET_ERROR_MSG  /* Need to set the error message */
    } non_ssl_request;

    /* Track the handshake/renegotiation state for the connection so
     * that all client-initiated renegotiations can be rejected, as a
     * partial fix for CVE-2009-3555. */
    enum {
        RENEG_INIT = 0, /* Before initial handshake */
        RENEG_REJECT,   /* After initial handshake; any client-initiated
                         * renegotiation should be rejected */
        RENEG_ALLOW,    /* A server-initiated renegotiation is taking
                         * place (as dictated by configuration) */
        RENEG_ABORT     /* Renegotiation initiated by client, abort the
                         * connection */
    } reneg_state;

    server_rec *server;
    SSLDirConfigRec *dc;
    
    const char *cipher_suite; /* cipher suite used in last reneg */
    int service_unavailable;  /* thouugh we negotiate SSL, no requests will be served */
    int vhost_found;          /* whether we found vhost from SNI already */
} SSLConnRec;


typedef struct {
    pid_t           pid;
    apr_pool_t     *pPool;
    BOOL            bFixed;

    /* OpenSSL SSL_SESS_CACHE_* flags: */
    long            sesscache_mode;

    /* The configured provider, and associated private data
     * structure. */
    const ap_socache_provider_t *sesscache;
    ap_socache_instance_t *sesscache_context;

    apr_global_mutex_t   *pMutex;
    apr_array_header_t   *aRandSeed;
    apr_hash_t     *tVHostKeys;

    /* A hash table of pointers to ssl_asn1_t structures.  The structures
     * are used to store private keys in raw DER format (serialized OpenSSL
     * PrivateKey structures).  The table is indexed by (vhost-id,
     * index), for example the string "vhost.example.com:443:0". */
    apr_hash_t     *tPrivateKey;

#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
    const char     *szCryptoDevice;
#endif

#ifdef HAVE_OCSP_STAPLING
    const ap_socache_provider_t *stapling_cache;
    ap_socache_instance_t *stapling_cache_context;
    apr_global_mutex_t   *stapling_cache_mutex;
    apr_global_mutex_t   *stapling_refresh_mutex;
#endif
} SSLModConfigRec;

struct SSLSrvConfigRec {
    SSLModConfigRec *mc;
    ssl_enabled_t    enabled;
    const char      *vhost_id;
    int              vhost_id_len;
    int              session_cache_timeout;
    BOOL             cipher_server_pref;
    BOOL             insecure_reneg;
    modssl_ctx_t    *server;
#ifdef HAVE_TLSEXT
    ssl_enabled_t    strict_sni_vhost_check;
#endif
#ifdef HAVE_FIPS
    BOOL             fips;
#endif
#ifndef OPENSSL_NO_COMP
    BOOL             compression;
#endif
    BOOL             session_tickets;
};

struct SSLDirConfigRec {
    BOOL          bSSLRequired;
    apr_array_header_t *aRequirement;
    ssl_opt_t     nOptions;
    ssl_opt_t     nOptionsAdd;
    ssl_opt_t     nOptionsDel;
    const char   *szCipherSuite;
    ssl_verify_t  nVerifyClient;
    int           nVerifyDepth;
    const char   *szUserName;
    apr_size_t    nRenegBufferSize;

    modssl_ctx_t *proxy;
    BOOL          proxy_enabled;
    BOOL          proxy_post_config;
};