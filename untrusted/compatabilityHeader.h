#include "user_types.h"
typedef WOLFSSL_SSL_IDENTIFIER SSL;
typedef WOLFSSL_SSL_CTX_IDENTIFIER SSL_CTX;
typedef WOLFSSL_SSL_SESSION_IDENTIFIER SSL_SESSION;

typedef WOLFSSL_X509_IDENTIFIER X509;
typedef WOLFSSL_X509_CTX_IDENTIFIER X509;
typedef WOLFSSL_DH_IDENTIFIER DH;
typedef WOLFSSL_EVP_PKEY_IDENTIFIER EVP_PKEY;
typedef WOLFSSL_BIO_IDENTIFIER BIO;
typedef WOLFSSL_509_STORE_IDENTIFIER X509_STORE;
typedef WOLFSSL_509_STORE_CTX_IDENTIFIER X509_STORE_CTX;
typedef WOLFSSL_EC_GROUP_IDENTIFIER EC_GROUP;
typedef WOLFSSL_OCSP_RESPONSE_IDENTIFIER OCSP_RESPONSE;
typedef WOLFSSL_OCSP_REQUEST_IDENTIFIER OCSP_REQUEST;
typedef WOLFSSL_X509_NAME_ENTRY_IDENTIFIER X509_NAME_ENTRY;
typedef WOLFSSL_X509_NAME_IDENTIFIER X509_NAME;
typedef WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER BASIC_CONSTRAINTS;

typedef WOLFSSL_ASN1_INTEGER_IDENTIFIER ASN1_INTEGER;
typedef WOLFSSL_ASN1_STRING_IDENTIFIER ASN1_STRING;
typedef WOLFSSL_ASN1_TYPE_IDENTIFIER ASN1_TYPE;
typedef WOLFSSL_ASN1_OBJECT_IDENTIFIER ASN1_OBJECT;

typedef WOLFSSL_BIGNUM_IDENTIFIER BIGNUM;
typedef WOLFSSL_STACK_IDENTIFIER SSL_STACK;
typedef WOLFSSL_GENERAL_NAME_IDENTIFIER GENERAL_NAME;



#define SSL_SENT_SHUTDOWN 1

#define _X509_V_OK 0

typedef int (*stack_cmp_func)(const void **a, const void **b);
typedef struct stack_st {
  /* num contains the number of valid pointers in |data|. */
  unsigned int num;
  void **data;
  /* sorted is non-zero if the values pointed to by |data| are in ascending
   * order, based on |comp|. */
  unsigned int sorted;
  /* num_alloc contains the number of pointers allocated in the buffer pointed
   * to by |data|, which may be larger than |num|. */
  unsigned int num_alloc;
  /* comp is an optional comparision function. */
  stack_cmp_func comp;
} _STACK;

#define STACK_OF(type) struct stack_st_##type

#define DEFINE_STACK_OF(type) STACK_OF(type) {_STACK stack;};

enum
{
    NID_undef = 0,
    NID_netscape_cert_type = NID_undef,
    NID_des = 66,
    NID_des3 = 67,
    NID_sha256 = 672,
    NID_sha384 = 673,
    NID_sha512 = 674,
    NID_hw_name_oid = 73,
    NID_id_pkix_OCSP_basic = 74,
    NID_any_policy = 75,
    NID_anyExtendedKeyUsage = 76,
    NID_givenName = 99,
    NID_initials = 101,
    NID_title = 106,
    NID_description = 107,
    NID_basic_constraints = 133,
    NID_key_usage = 129,     /* 2.5.29.15 */
    NID_ext_key_usage = 151, /* 2.5.29.37 */
    NID_subject_key_identifier = 128,
    NID_authority_key_identifier = 149,
    NID_private_key_usage_period = 130, /* 2.5.29.16 */
    NID_subject_alt_name = 131,
    NID_issuer_alt_name = 132,
    NID_info_access = 69,
    NID_sinfo_access = 79,      /* id-pe 11 */
    NID_name_constraints = 144, /* 2.5.29.30 */
    NID_crl_distribution_points = 145, /* 2.5.29.31 */
    NID_certificate_policies = 146,
    NID_policy_mappings = 147,
    NID_policy_constraints = 150,
    NID_inhibit_any_policy = 168,      /* 2.5.29.54 */
    NID_tlsfeature = 1020,             /* id-pe 24 */
    NID_commonName = 0x03,             /* matches ASN_COMMON_NAME in asn.h */


    NID_surname = 0x04,                /* SN */
    NID_serialNumber = 0x05,           /* serialNumber */
    NID_countryName = 0x06,            /* C  */
    NID_localityName = 0x07,           /* L  */
    NID_stateOrProvinceName = 0x08,    /* ST */
    NID_organizationName = 0x0a,       /* O  */
    NID_organizationalUnitName = 0x0b, /* OU */
    NID_domainComponent = 0x19,        /* matches ASN_DOMAIN_COMPONENT in asn.h */
    NID_emailAddress = 0x30,           /* emailAddress */
    NID_id_on_dnsSRV = 82,             /* 1.3.6.1.5.5.7.8.7 */
    NID_ms_upn = 265,                  /* 1.3.6.1.4.1.311.20.2.3 */

    NID_X9_62_prime_field = 406        /* 1.2.840.10045.1.1 */
};

/* Type for ASN1_print_ex */
#define ASN1_STRFLGS_ESC_2253           1
#define ASN1_STRFLGS_ESC_CTRL           2
#define _ASN1_STRFLGS_ESC_MSB            4
#define ASN1_STRFLGS_ESC_QUOTE          8
#define ASN1_STRFLGS_UTF8_CONVERT       0x10
#define ASN1_STRFLGS_IGNORE_TYPE        0x20
#define ASN1_STRFLGS_SHOW_TYPE          0x40
#define ASN1_STRFLGS_DUMP_ALL           0x80
#define ASN1_STRFLGS_DUMP_UNKNOWN       0x100
#define ASN1_STRFLGS_DUMP_DER           0x200



enum {
#ifdef HAVE_OCSP
    /* OCSP Flags */
    OCSP_NOCERTS     = 1,
    OCSP_NOINTERN    = 2,
    OCSP_NOSIGS      = 4,
    OCSP_NOCHAIN     = 8,
    OCSP_NOVERIFY    = 16,
    OCSP_NOEXPLICIT  = 32,
    OCSP_NOCASIGN    = 64,
    OCSP_NODELEGATED = 128,
    OCSP_NOCHECKS    = 256,
    OCSP_TRUSTOTHER  = 512,
    OCSP_RESPID_KEY  = 1024,
    OCSP_NOTIME      = 2048,

    /* OCSP Types */
    OCSP_CERTID   = 2,
    OCSP_REQUEST  = 4,
    OCSP_RESPONSE = 8,
    OCSP_BASICRESP = 16,
#endif

    ASN1_GENERALIZEDTIME = 4,
    SSL_MAX_SSL_SESSION_ID_LENGTH = 32,

    SSL_ST_CONNECT = 0x1000,
    SSL_ST_ACCEPT  = 0x2000,
    SSL_ST_MASK    = 0x0FFF,

    SSL_CB_LOOP = 0x01,
    SSL_CB_EXIT = 0x02,
    SSL_CB_READ = 0x04,
    SSL_CB_WRITE = 0x08,
    SSL_CB_HANDSHAKE_START = 0x10,
    SSL_CB_HANDSHAKE_DONE = 0x20,
    SSL_CB_ALERT = 0x4000,
    SSL_CB_READ_ALERT = (SSL_CB_ALERT | SSL_CB_READ),
    SSL_CB_WRITE_ALERT = (SSL_CB_ALERT | SSL_CB_WRITE),
    SSL_CB_ACCEPT_LOOP = (SSL_ST_ACCEPT | SSL_CB_LOOP),
    SSL_CB_ACCEPT_EXIT = (SSL_ST_ACCEPT | SSL_CB_EXIT),
    SSL_CB_CONNECT_LOOP = (SSL_ST_CONNECT | SSL_CB_LOOP),
    SSL_CB_CONNECT_EXIT = (SSL_ST_CONNECT | SSL_CB_EXIT),
    SSL_CB_MODE_READ = 1,
    SSL_CB_MODE_WRITE = 2,

    SSL_MODE_ENABLE_PARTIAL_WRITE = 2,
    SSL_MODE_AUTO_RETRY = 3, /* wolfSSL default is to block with blocking io
                              * and auto retry */
    SSL_MODE_RELEASE_BUFFERS = -1, /* For libwebsockets build. No current use. */

    BIO_FLAGS_BASE64_NO_NL = 1,
    BIO_CLOSE   = 1,
    BIO_NOCLOSE = 0,

    X509_FILETYPE_PEM = 8,
    X509_LU_X509      = 9,
    X509_LU_CRL       = 12,

    X509_V_OK                                    = 0,
    X509_V_ERR_CRL_SIGNATURE_FAILURE             = 13,
    X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD    = 14,
    X509_V_ERR_CRL_HAS_EXPIRED                   = 15,
    X509_V_ERR_CERT_REVOKED                      = 16,
    X509_V_ERR_CERT_CHAIN_TOO_LONG               = 17,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT         = 18,
    X509_V_ERR_CERT_NOT_YET_VALID                = 19,
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD    = 20,
    X509_V_ERR_CERT_HAS_EXPIRED                  = 21,
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD     = 22,
    X509_V_ERR_CERT_REJECTED                     = 23,
    /* Required for Nginx  */
    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT       = 24,
    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN         = 25,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 26,
    X509_V_ERR_CERT_UNTRUSTED                    = 27,
    X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE   = 28,
    X509_V_ERR_SUBJECT_ISSUER_MISMATCH           = 29,
    /* additional X509_V_ERR_* enums not used in wolfSSL */
    X509_V_ERR_UNABLE_TO_GET_CRL,
    X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
    X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
    X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
    X509_V_ERR_CERT_SIGNATURE_FAILURE,
    X509_V_ERR_CRL_NOT_YET_VALID,
    X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
    X509_V_ERR_OUT_OF_MEM,
    X509_V_ERR_INVALID_CA,
    X509_V_ERR_PATH_LENGTH_EXCEEDED,
    X509_V_ERR_INVALID_PURPOSE,
    X509_V_ERR_AKID_SKID_MISMATCH,
    X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH,
    X509_V_ERR_KEYUSAGE_NO_CERTSIGN,
    X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER,
    X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION,
    X509_V_ERR_KEYUSAGE_NO_CRL_SIGN,
    X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION,
    X509_V_ERR_INVALID_NON_CA,
    X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED,
    X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE,
    X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED,
    X509_V_ERR_INVALID_EXTENSION,
    X509_V_ERR_INVALID_POLICY_EXTENSION,
    X509_V_ERR_NO_EXPLICIT_POLICY,
    X509_V_ERR_UNNESTED_RESOURCE,
    X509_V_ERR_APPLICATION_VERIFICATION,

    X509_R_CERT_ALREADY_IN_HASH_TABLE,

    XN_FLAG_SPC_EQ  = (1 << 23),
    XN_FLAG_SEP_CPLUS_SPC = (2 << 16),
    XN_FLAG_ONELINE = 0,
    XN_FLAG_RFC2253 = 1,
    XN_FLAG_DN_REV = (1 << 20),

    CRYPTO_LOCK = 1,
    CRYPTO_NUM_LOCKS = 10,

    ASN1_STRFLGS_ESC_MSB = 4
};


#define WOLFSSL_ASN1_BOOLEAN int
#define GEN_OTHERNAME   0
#define GEN_EMAIL       1
#define GEN_DNS         2
#define GEN_X400        3
#define GEN_DIRNAME     4
#define GEN_EDIPARTY    5
#define GEN_URI         6
#define GEN_IPADD       7
#define GEN_RID         8

#define V_ASN1_IA5STRING     22
#define V_ASN1_UTF8STRING    12


enum { /* ssl Constants */
    WOLFSSL_ERROR_NONE      =  0,   /* for most functions */
    WOLFSSL_FAILURE         =  0,   /* for some functions */
    WOLFSSL_SUCCESS         =  1,
    WOLFSSL_SHUTDOWN_NOT_DONE =  2,  /* call wolfSSL_shutdown again to complete */

    WOLFSSL_ALPN_NOT_FOUND  = -9,
    WOLFSSL_BAD_CERTTYPE    = -8,
    WOLFSSL_BAD_STAT        = -7,
    WOLFSSL_BAD_PATH        = -6,
    WOLFSSL_BAD_FILETYPE    = -5,
    WOLFSSL_BAD_FILE        = -4,
    WOLFSSL_NOT_IMPLEMENTED = -3,
    WOLFSSL_UNKNOWN         = -2,
    WOLFSSL_FATAL_ERROR     = -1,

    WOLFSSL_FILETYPE_ASN1    = 2,
    WOLFSSL_FILETYPE_PEM     = 1,
    WOLFSSL_FILETYPE_DEFAULT = 2, /* ASN1 */
    WOLFSSL_FILETYPE_RAW     = 3, /* NTRU raw key blob */

    WOLFSSL_VERIFY_NONE                 = 0,
    WOLFSSL_VERIFY_PEER                 = 1,
    WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
    WOLFSSL_VERIFY_CLIENT_ONCE          = 4,
    WOLFSSL_VERIFY_FAIL_EXCEPT_PSK      = 8,

    WOLFSSL_SESS_CACHE_OFF                = 0x0000,
    WOLFSSL_SESS_CACHE_CLIENT             = 0x0001,
    WOLFSSL_SESS_CACHE_SERVER             = 0x0002,
    WOLFSSL_SESS_CACHE_BOTH               = 0x0003,
    WOLFSSL_SESS_CACHE_NO_AUTO_CLEAR      = 0x0008,
    WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100,
    WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE  = 0x0200,
    WOLFSSL_SESS_CACHE_NO_INTERNAL        = 0x0300,

    WOLFSSL_ERROR_WANT_READ        =  2,
    WOLFSSL_ERROR_WANT_WRITE       =  3,
    WOLFSSL_ERROR_WANT_CONNECT     =  7,
    WOLFSSL_ERROR_WANT_ACCEPT      =  8,
    WOLFSSL_ERROR_SYSCALL          =  5,
    WOLFSSL_ERROR_WANT_X509_LOOKUP = 83,
    WOLFSSL_ERROR_ZERO_RETURN      =  6,
    WOLFSSL_ERROR_SSL              = 85,

    WOLFSSL_SENT_SHUTDOWN     = 1,
    WOLFSSL_RECEIVED_SHUTDOWN = 2,
    WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4,

    WOLFSSL_R_SSL_HANDSHAKE_FAILURE           = 101,
    WOLFSSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102,
    WOLFSSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103,
    WOLFSSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104,

    WOLF_PEM_BUFSIZE = 1024
};

enum {
    SSL_OP_MICROSOFT_SESS_ID_BUG                  = 0x00000001,
    SSL_OP_NETSCAPE_CHALLENGE_BUG                 = 0x00000002,
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG       = 0x00000004,
    SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG            = 0x00000008,
    SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER             = 0x00000010,
    SSL_OP_MSIE_SSLV2_RSA_PADDING                 = 0x00000020,
    SSL_OP_SSLEAY_080_CLIENT_DH_BUG               = 0x00000040,
    SSL_OP_TLS_D5_BUG                             = 0x00000080,
    SSL_OP_TLS_BLOCK_PADDING_BUG                  = 0x00000100,
    SSL_OP_TLS_ROLLBACK_BUG                       = 0x00000200,
    SSL_OP_EPHEMERAL_RSA                          = 0x00000800,
    WOLFSSL_OP_NO_SSLv3                           = 0x00001000,
    WOLFSSL_OP_NO_TLSv1                           = 0x00002000,
    SSL_OP_PKCS1_CHECK_1                          = 0x00004000,
    SSL_OP_PKCS1_CHECK_2                          = 0x00008000,
    SSL_OP_NETSCAPE_CA_DN_BUG                     = 0x00010000,
    SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG        = 0x00020000,
    SSL_OP_SINGLE_DH_USE                          = 0x00040000,
    SSL_OP_NO_TICKET                              = 0x00080000,
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS            = 0x00100000,
    SSL_OP_NO_QUERY_MTU                           = 0x00200000,
    SSL_OP_COOKIE_EXCHANGE                        = 0x00400000,
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00800000,
    SSL_OP_SINGLE_ECDH_USE                        = 0x01000000,
    SSL_OP_CIPHER_SERVER_PREFERENCE               = 0x02000000,
    WOLFSSL_OP_NO_TLSv1_1                         = 0x04000000,
    WOLFSSL_OP_NO_TLSv1_2                         = 0x08000000,
    SSL_OP_NO_COMPRESSION                         = 0x10000000,
    WOLFSSL_OP_NO_TLSv1_3                         = 0x20000000,
    WOLFSSL_OP_NO_SSLv2                           = 0x40000000,
    SSL_OP_ALL   =
                    (SSL_OP_MICROSOFT_SESS_ID_BUG
                  | SSL_OP_NETSCAPE_CHALLENGE_BUG
                  | SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
                  | SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
                  | SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
                  | SSL_OP_MSIE_SSLV2_RSA_PADDING
                  | SSL_OP_SSLEAY_080_CLIENT_DH_BUG
                  | SSL_OP_TLS_D5_BUG
                  | SSL_OP_TLS_BLOCK_PADDING_BUG
                  | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
                  | SSL_OP_TLS_ROLLBACK_BUG),
};

/* for compatibility these must be macros */
#define SSL_OP_NO_SSLv2   WOLFSSL_OP_NO_SSLv2
#define SSL_OP_NO_SSLv3   WOLFSSL_OP_NO_SSLv3
#define SSL_OP_NO_TLSv1   WOLFSSL_OP_NO_TLSv1
#define SSL_OP_NO_TLSv1_1 WOLFSSL_OP_NO_TLSv1_1
#define SSL_OP_NO_TLSv1_2 WOLFSSL_OP_NO_TLSv1_2

#define SSL_set_tlsext_host_name

#define OPENSSL_VERSION_NUMBER 0x1000100fL
