#pragma once
#include "user_types.h"
typedef WOLFSSL_SSL_IDENTIFIER SSL;
typedef WOLFSSL_SSL_CTX_IDENTIFIER SSL_CTX;
typedef WOLFSSL_SSL_SESSION_IDENTIFIER SSL_SESSION;
typedef WOLFSSL_SSL_CIPHER_IDENTIFIER SSL_CIPHER;

typedef WOLFSSL_X509_IDENTIFIER X509;
typedef WOLFSSL_X509_CTX_IDENTIFIER X509;
typedef WOLFSSL_X509_EXTENSION_IDENTIFIER X509_EXTENSION;
typedef WOLFSSL_509_STORE_IDENTIFIER X509_STORE;
typedef WOLFSSL_509_STORE_CTX_IDENTIFIER X509_STORE_CTX;
typedef WOLFSSL_X509_ALGOR_IDENTIFIER X509_ALGOR;
typedef WOLFSSL_X509_PUBKEY_IDENTIFIER X509_PUBKEY;

typedef WOLFSSL_DH_IDENTIFIER DH;
typedef WOLFSSL_BIO_IDENTIFIER BIO;
typedef WOLFSSL_BIO_METHOD_IDENTIFIER BIO_METHOD;

typedef WOLFSSL_EC_GROUP_IDENTIFIER EC_GROUP;
typedef WOLFSSL_OCSP_RESPONSE_IDENTIFIER OCSP_RESPONSE;
typedef WOLFSSL_OCSP_REQUEST_IDENTIFIER OCSP_REQUEST;
typedef WOLFSSL_X509_NAME_ENTRY_IDENTIFIER X509_NAME_ENTRY;
typedef WOLFSSL_X509_NAME_IDENTIFIER X509_NAME;
typedef WOLFSSL_BASIC_CONSTRAINTS_IDENTIFIER BASIC_CONSTRAINTS;

typedef WOLFSSL_ASN1_INTEGER_IDENTIFIER ASN1_INTEGER;
typedef WOLFSSL_ASN1_TIME_IDENTIFIER ASN1_TIME;
typedef WOLFSSL_ASN1_STRING_IDENTIFIER ASN1_STRING;
typedef WOLFSSL_ASN1_TYPE_IDENTIFIER ASN1_TYPE;
typedef WOLFSSL_ASN1_OBJECT_IDENTIFIER ASN1_OBJECT;

typedef WOLFSSL_BIGNUM_IDENTIFIER BIGNUM;
typedef WOLFSSL_STACK_IDENTIFIER SSL_STACK;
typedef WOLFSSL_GENERAL_NAME_IDENTIFIER GENERAL_NAME;

typedef WOLFSSL_EVP_PKEY_IDENTIFIER EVP_PKEY;
typedef WOLFSSL_EVP_MD_IDENTIFIER EVP_MD;

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

#define OPENSSL_VERSION_NUMBER 0x1000101fL


/* BIO CTRL */
#define BIO_CTRL_RESET             1
#define BIO_CTRL_EOF               2
#define BIO_CTRL_INFO              3
#define BIO_CTRL_PUSH              6
#define BIO_CTRL_POP               7
#define BIO_CTRL_GET_CLOSE         8
#define BIO_CTRL_SET_CLOSE         9
#define BIO_CTRL_PENDING           10
#define BIO_CTRL_FLUSH             11
#define BIO_CTRL_DUP               12
#define BIO_CTRL_WPENDING          13

#define BIO_C_SET_FILE_PTR              106
#define BIO_C_GET_FILE_PTR              107
#define BIO_C_SET_FILENAME              108
#define BIO_C_SET_BUF_MEM               114
#define BIO_C_GET_BUF_MEM_PTR           115
#define BIO_C_FILE_SEEK                 128
#define BIO_C_SET_BUF_MEM_EOF_RETURN    130
#define BIO_C_SET_WRITE_BUF_SIZE        136
#define BIO_C_MAKE_BIO_PAIR             138

#define BIO_CTRL_DGRAM_QUERY_MTU   40

#define BIO_NOCLOSE                0x00
#define BIO_CLOSE                  0x01

#define BIO_FP_WRITE               0x04


enum BIO_CB_OPS {
    WOLFSSL_BIO_CB_FREE   = 0x01,
    WOLFSSL_BIO_CB_READ   = 0x02,
    WOLFSSL_BIO_CB_WRITE  = 0x03,
    WOLFSSL_BIO_CB_PUTS   = 0x04,
    WOLFSSL_BIO_CB_GETS   = 0x05,
    WOLFSSL_BIO_CB_CTRL   = 0x06,
    WOLFSSL_BIO_CB_RETURN = 0x80
};

#define SSL_CTRL_CHAIN       88
#define GEN_IPADD            7
#define ERR_LIB_SSL          20
#define SSL_R_SHORT_READ     10
#define ERR_R_PEM_LIB        9
#define V_ASN1_IA5STRING     22
#define V_ASN1_UTF8STRING    12
#define SSL_CTRL_MODE        33
enum wolfSSL_ErrorCodes {
    INPUT_CASE_ERROR             = -301,   /* process input state error */
    PREFIX_ERROR                 = -302,   /* bad index to key rounds  */
    MEMORY_ERROR                 = -303,   /* out of memory            */
    VERIFY_FINISHED_ERROR        = -304,   /* verify problem on finished */
    VERIFY_MAC_ERROR             = -305,   /* verify mac problem       */
    PARSE_ERROR                  = -306,   /* parse error on header    */
    UNKNOWN_HANDSHAKE_TYPE       = -307,   /* weird handshake type     */
    SOCKET_ERROR_E               = -308,   /* error state on socket    */
    SOCKET_NODATA                = -309,   /* expected data, not there */
    INCOMPLETE_DATA              = -310,   /* don't have enough data to
                                              complete task            */
    UNKNOWN_RECORD_TYPE          = -311,   /* unknown type in record hdr */
    DECRYPT_ERROR                = -312,   /* error during decryption  */
    FATAL_ERROR                  = -313,   /* recvd alert fatal error  */
    ENCRYPT_ERROR                = -314,   /* error during encryption  */
    FREAD_ERROR                  = -315,   /* fread problem            */
    NO_PEER_KEY                  = -316,   /* need peer's key          */
    NO_PRIVATE_KEY               = -317,   /* need the private key     */
    RSA_PRIVATE_ERROR            = -318,   /* error during rsa priv op */
    NO_DH_PARAMS                 = -319,   /* server missing DH params */
    BUILD_MSG_ERROR              = -320,   /* build message failure    */

    BAD_HELLO                    = -321,   /* client hello malformed   */
    DOMAIN_NAME_MISMATCH         = -322,   /* peer subject name mismatch */
    WANT_READ                    = -323,   /* want read, call again    */
    NOT_READY_ERROR              = -324,   /* handshake layer not ready */
    IPADDR_MISMATCH              = -325,   /* peer ip address mismatch */
    VERSION_ERROR                = -326,   /* record layer version error */
    WANT_WRITE                   = -327,   /* want write, call again   */
    BUFFER_ERROR                 = -328,   /* malformed buffer input   */
    VERIFY_CERT_ERROR            = -329,   /* verify cert error        */
    VERIFY_SIGN_ERROR            = -330,   /* verify sign error        */
    CLIENT_ID_ERROR              = -331,   /* psk client identity error  */
    SERVER_HINT_ERROR            = -332,   /* psk server hint error  */
    PSK_KEY_ERROR                = -333,   /* psk key error  */

    GETTIME_ERROR                = -337,   /* gettimeofday failed ??? */
    GETITIMER_ERROR              = -338,   /* getitimer failed ??? */
    SIGACT_ERROR                 = -339,   /* sigaction failed ??? */
    SETITIMER_ERROR              = -340,   /* setitimer failed ??? */
    LENGTH_ERROR                 = -341,   /* record layer length error */
    PEER_KEY_ERROR               = -342,   /* can't decode peer key */
    ZERO_RETURN                  = -343,   /* peer sent close notify */
    SIDE_ERROR                   = -344,   /* wrong client/server type */
    NO_PEER_CERT                 = -345,   /* peer didn't send key */
    NTRU_KEY_ERROR               = -346,   /* NTRU key error  */
    NTRU_DRBG_ERROR              = -347,   /* NTRU drbg error  */
    NTRU_ENCRYPT_ERROR           = -348,   /* NTRU encrypt error  */
    NTRU_DECRYPT_ERROR           = -349,   /* NTRU decrypt error  */
    ECC_CURVETYPE_ERROR          = -350,   /* Bad ECC Curve Type */
    ECC_CURVE_ERROR              = -351,   /* Bad ECC Curve */
    ECC_PEERKEY_ERROR            = -352,   /* Bad Peer ECC Key */
    ECC_MAKEKEY_ERROR            = -353,   /* Bad Make ECC Key */
    ECC_EXPORT_ERROR             = -354,   /* Bad ECC Export Key */
    ECC_SHARED_ERROR             = -355,   /* Bad ECC Shared Secret */
    NOT_CA_ERROR                 = -357,   /* Not a CA cert error */

    BAD_CERT_MANAGER_ERROR       = -359,   /* Bad Cert Manager */
    OCSP_CERT_REVOKED            = -360,   /* OCSP Certificate revoked */
    CRL_CERT_REVOKED             = -361,   /* CRL Certificate revoked */
    CRL_MISSING                  = -362,   /* CRL Not loaded */
    MONITOR_SETUP_E              = -363,   /* CRL Monitor setup error */
    THREAD_CREATE_E              = -364,   /* Thread Create Error */
    OCSP_NEED_URL                = -365,   /* OCSP need an URL for lookup */
    OCSP_CERT_UNKNOWN            = -366,   /* OCSP responder doesn't know */
    OCSP_LOOKUP_FAIL             = -367,   /* OCSP lookup not successful */
    MAX_CHAIN_ERROR              = -368,   /* max chain depth exceeded */
    COOKIE_ERROR                 = -369,   /* dtls cookie error */
    SEQUENCE_ERROR               = -370,   /* dtls sequence error */
    SUITES_ERROR                 = -371,   /* suites pointer error */

    OUT_OF_ORDER_E               = -373,   /* out of order message */
    BAD_KEA_TYPE_E               = -374,   /* bad KEA type found */
    SANITY_CIPHER_E              = -375,   /* sanity check on cipher error */
    RECV_OVERFLOW_E              = -376,   /* RXCB returned more than read */
    GEN_COOKIE_E                 = -377,   /* Generate Cookie Error */
    NO_PEER_VERIFY               = -378,   /* Need peer cert verify Error */
    FWRITE_ERROR                 = -379,   /* fwrite problem */
    CACHE_MATCH_ERROR            = -380,   /* Cache hdr match error */
    UNKNOWN_SNI_HOST_NAME_E      = -381,   /* Unrecognized host name Error */
    UNKNOWN_MAX_FRAG_LEN_E       = -382,   /* Unrecognized max frag len Error */
    KEYUSE_SIGNATURE_E           = -383,   /* KeyUse digSignature error */
    KEYUSE_ENCIPHER_E            = -385,   /* KeyUse keyEncipher error */
    EXTKEYUSE_AUTH_E             = -386,   /* ExtKeyUse server|client_auth */
    SEND_OOB_READ_E              = -387,   /* Send Cb out of bounds read */
    SECURE_RENEGOTIATION_E       = -388,   /* Invalid Renegotiation Info */
    SESSION_TICKET_LEN_E         = -389,   /* Session Ticket too large */
    SESSION_TICKET_EXPECT_E      = -390,   /* Session Ticket missing   */
    SCR_DIFFERENT_CERT_E         = -391,   /* SCR Different cert error  */
    SESSION_SECRET_CB_E          = -392,   /* Session secret Cb fcn failure */
    NO_CHANGE_CIPHER_E           = -393,   /* Finished before change cipher */
    SANITY_MSG_E                 = -394,   /* Sanity check on msg order error */
    DUPLICATE_MSG_E              = -395,   /* Duplicate message error */
    SNI_UNSUPPORTED              = -396,   /* SSL 3.0 does not support SNI */
    SOCKET_PEER_CLOSED_E         = -397,   /* Underlying transport closed */
    BAD_TICKET_KEY_CB_SZ         = -398,   /* Bad session ticket key cb size */
    BAD_TICKET_MSG_SZ            = -399,   /* Bad session ticket msg size    */
    BAD_TICKET_ENCRYPT           = -400,   /* Bad user ticket encrypt        */
    DH_KEY_SIZE_E                = -401,   /* DH Key too small */
    SNI_ABSENT_ERROR             = -402,   /* No SNI request. */
    RSA_SIGN_FAULT               = -403,   /* RSA Sign fault */
    HANDSHAKE_SIZE_ERROR         = -404,   /* Handshake message too large */
    UNKNOWN_ALPN_PROTOCOL_NAME_E = -405,   /* Unrecognized protocol name Error*/
    BAD_CERTIFICATE_STATUS_ERROR = -406,   /* Bad certificate status message */
    OCSP_INVALID_STATUS          = -407,   /* Invalid OCSP Status */
    OCSP_WANT_READ               = -408,   /* OCSP callback response WOLFSSL_CBIO_ERR_WANT_READ */
    RSA_KEY_SIZE_E               = -409,   /* RSA key too small */
    ECC_KEY_SIZE_E               = -410,   /* ECC key too small */
    DTLS_EXPORT_VER_E            = -411,   /* export version error */
    INPUT_SIZE_E                 = -412,   /* input size too big error */
    CTX_INIT_MUTEX_E             = -413,   /* initialize ctx mutex error */
    EXT_MASTER_SECRET_NEEDED_E   = -414,   /* need EMS enabled to resume */
    DTLS_POOL_SZ_E               = -415,   /* exceeded DTLS pool size */
    DECODE_E                     = -416,   /* decode handshake message error */
    HTTP_TIMEOUT                 = -417,   /* HTTP timeout for OCSP or CRL req */
    WRITE_DUP_READ_E             = -418,   /* Write dup write side can't read */
    WRITE_DUP_WRITE_E            = -419,   /* Write dup read side can't write */
    INVALID_CERT_CTX_E           = -420,   /* TLS cert ctx not matching */
    BAD_KEY_SHARE_DATA           = -421,   /* Key Share data invalid */
    MISSING_HANDSHAKE_DATA       = -422,   /* Handshake message missing data */
    BAD_BINDER                   = -423,   /* Binder does not match */
    EXT_NOT_ALLOWED              = -424,   /* Extension not allowed in msg */
    INVALID_PARAMETER            = -425,   /* Security parameter invalid */
    MCAST_HIGHWATER_CB_E         = -426,   /* Multicast highwater cb err */
    ALERT_COUNT_E                = -427,   /* Alert Count exceeded err */
    EXT_MISSING                  = -428,   /* Required extension not found */
    UNSUPPORTED_EXTENSION        = -429,   /* TLSX not requested by client */
    PRF_MISSING                  = -430,   /* PRF not compiled in */
    DTLS_RETX_OVER_TX            = -431,   /* Retransmit DTLS flight over */
    DH_PARAMS_NOT_FFDHE_E        = -432,   /* DH params from server not FFDHE */
    TCA_INVALID_ID_TYPE          = -433,   /* TLSX TCA ID type invalid */
    TCA_ABSENT_ERROR             = -434,   /* TLSX TCA ID no response */
    TSIP_MAC_DIGSZ_E             = -435,   /* Invalid MAC size for TSIP */
    CLIENT_CERT_CB_ERROR         = -436,   /* Client cert callback error */
    SSL_SHUTDOWN_ALREADY_DONE_E  = -437,   /* Shutdown called redundantly */
    TLS13_SECRET_CB_E            = -438,   /* TLS1.3 secret Cb fcn failure */

    /* add strings to wolfSSL_ERR_reason_error_string in internal.c !!!!! */

    /* begin negotiation parameter errors */
    UNSUPPORTED_SUITE            = -500,   /* unsupported cipher suite */
    MATCH_SUITE_ERROR            = -501,   /* can't match cipher suite */
    COMPRESSION_ERROR            = -502,   /* compression mismatch */
    KEY_SHARE_ERROR              = -503,   /* key share mismatch */
    POST_HAND_AUTH_ERROR         = -504,   /* client won't do post-hand auth */
    HRR_COOKIE_ERROR             = -505    /* HRR msg cookie mismatch */
    /* end negotiation parameter errors only 10 for now */
    /* add strings to wolfSSL_ERR_reason_error_string in internal.c !!!!! */

    /* no error stings go down here, add above negotiation errors !!!! */
};
/* Nginx checks these to see if the error was a handshake error. */
#define SSL_R_BAD_CHANGE_CIPHER_SPEC               LENGTH_ERROR
#define SSL_R_BLOCK_CIPHER_PAD_IS_WRONG            BUFFER_E
#define SSL_R_DIGEST_CHECK_FAILED                  VERIFY_MAC_ERROR
#define SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST        SUITES_ERROR
#define SSL_R_EXCESSIVE_MESSAGE_SIZE               BUFFER_ERROR
#define SSL_R_LENGTH_MISMATCH                      LENGTH_ERROR
#define SSL_R_NO_CIPHERS_SPECIFIED                 SUITES_ERROR
#define SSL_R_NO_COMPRESSION_SPECIFIED             COMPRESSION_ERROR
#define SSL_R_NO_SHARED_CIPHER                     MATCH_SUITE_ERROR
#define SSL_R_RECORD_LENGTH_MISMATCH               HANDSHAKE_SIZE_ERROR
#define SSL_R_UNEXPECTED_MESSAGE                   OUT_OF_ORDER_E
#define SSL_R_UNEXPECTED_RECORD                    SANITY_MSG_E
#define SSL_R_UNKNOWN_ALERT_TYPE                   BUFFER_ERROR
#define SSL_R_UNKNOWN_PROTOCOL                     VERSION_ERROR
#define SSL_R_WRONG_VERSION_NUMBER                 VERSION_ERROR
#define SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC  ENCRYPT_ERROR
#define SSL_R_HTTPS_PROXY_REQUEST                  PARSE_ERROR
#define SSL_R_HTTP_REQUEST                         PARSE_ERROR
#define SSL_R_UNSUPPORTED_PROTOCOL                 VERSION_ERROR
#define BIO_TYPE_MEM  4 //WOLFSSL_BIO_MEMORY


#ifndef EVP_MAX_MD_SIZE
    #define EVP_MAX_MD_SIZE   64     /* sha512 */
#endif
#define LIBWOLFSSL_VERSION_STRING "4.3.0"
#define LIBWOLFSSL_VERSION_HEX 0x04003000
#define TLSEXT_NAMETYPE_host_name       0


int ERR_GET_LIB(unsigned long err);
int ERR_GET_REASON(unsigned long err);
unsigned long ERR_peek_error();
char* X509_verify_cert_error_string(long err);

#define OPENSSL_VERSION 0
const char* OpenSSL_version(int version);


#define NID_pkcs9_emailAddress          48


typedef struct _WOLFSSL_BUF_MEM {
    char*  data;   /* dereferenced */
    size_t length; /* current length */
    size_t max;    /* maximum length */
} WOLFSSL_BUF_MEM;
#define BUF_MEM WOLFSSL_BUF_MEM

const char* SSL_get_version(SSL s);
int SSL_session_reused(SSL s);
WOLFSSL_STACK_IDENTIFIER SSL_get_peer_cert_chain(SSL s);
char* SSL_get_servername(SSL, uint8_t);
SSL_SESSION SSL_get_session(SSL);
size_t SSL_get_peer_finished(SSL s, void *buf, size_t count);
size_t SSL_get_finished(SSL s, void *buf, size_t count);
unsigned int SSL_SESSION_get_compress_id(SSL_SESSION s);

X509 SSL_get_peer_certificate(SSL ssl);
X509 SSL_get_certificate(SSL ssl);
int X509_up_ref(X509);
char* X509_NAME_oneline(X509_NAME name, char* in, int sz);
int X509_get_signature_nid(X509);
ASN1_STRING X509_EXTENSION_get_data(X509_EXTENSION);
int X509_digest(X509 x509, EVP_MD digest, unsigned char* buffer, unsigned int* len);
uint8_t* SSL_SESSION_get_id(SSL_SESSION, unsigned int*);
void X509_free(X509);


void ASN1_OBJECT_free(ASN1_OBJECT);
EVP_MD EVP_get_digestbynid(int);
EVP_MD EVP_md5();
EVP_MD EVP_sha1();
EVP_MD EVP_sha256();

BIO BIO_new(BIO_METHOD);
BIO_METHOD BIO_s_mem();
int BIO_free();

int X509_NAME_print_ex(BIO, X509_NAME, int, unsigned long);

int BIO_get_mem_ptr(BIO, BUF_MEM**);
void BIO_vfree(BIO);
int BIO_pending(BIO);
int BIO_read(BIO, void*, int len);
void ERR_clear_error();

int X509V3_EXT_print(BIO, X509_EXTENSION, unsigned long, int);
ASN1_OBJECT X509_EXTENSION_get_object(X509_EXTENSION);
int OBJ_cmp(ASN1_OBJECT, ASN1_OBJECT);
int X509_get_ext_count(X509);

ASN1_OBJECT OBJ_txt2obj(const char*, int);


ASN1_TIME X509_get_notBefore(X509);
ASN1_TIME X509_get_notAfter(X509);
X509_NAME X509_get_subject_name(X509);
X509_NAME X509_get_issuer_name(X509);
X509_NAME_ENTRY X509_NAME_get_entry(X509_NAME, int loc);
ASN1_INTEGER X509_get_serialNumber(X509);

int OBJ_obj2nid(ASN1_OBJECT);
int ASN1_TIME_print(BIO bioId, ASN1_TIME timeId);

int i2a_ASN1_INTEGER(BIO bioId, ASN1_INTEGER asn1IntId);
BIGNUM ASN1_INTEGER_to_BN(ASN1_INTEGER);
long SSL_get_verify_result(SSL sslId);

void ASN1_STRING_free(ASN1_STRING);
int SSL_CIPHER_get_bits(SSL_CIPHER, int*);
SSL_CIPHER SSL_get_current_cipher(SSL);
char* SSL_CIPHER_get_name(SSL_CIPHER); 

X509_EXTENSION X509_get_ext(X509 x509id, int loc);
void BN_free(BIGNUM);
long X509_get_version(X509);
void X509_ALGOR_get0(ASN1_OBJECT* asn1ObjId, int *pptype, const void**ppval, X509_ALGOR algorId);
X509_ALGOR X509_get0_tbs_sigalg(X509 x509id);
X509_PUBKEY X509_get_X509_PUBKEY(X509 x509id);
int X509_NAME_entry_count(X509_NAME nameId);
int X509_PUBKEY_get0_param(ASN1_OBJECT* asn1ObjId, const unsigned char **pk, int *ppklen, void **pa, X509_PUBKEY pubId);

