#pragma once
#include <inttypes.h>
typedef uint64_t WOLFSSL_SSL_IDENTIFIER;
typedef uint64_t WOLFSSL_SSL_CTX_IDENTIFIER;
typedef uint64_t WOLFSSL_X509_IDENTIFIER;
typedef uint64_t WOLFSSL_X509_CTX_IDENTIFIER;
typedef uint64_t WOLFSSL_DH_IDENTIFIER;
typedef uint64_t WOLFSSL_EVP_PKEY_IDENTIFIER;
typedef uint64_t WOLFSSL_SESSION_IDENTIFIER;
typedef uint64_t WOLFSSL_BIO_IDENTIFIER;
typedef uint64_t WOLFSSL_509_STORE_IDENTIFIER;
typedef uint64_t WOLFSSL_509_STORE_CTX_IDENTIFIER;
typedef uint64_t WOLFSSL_EC_GROUP_IDENTIFIER;
typedef uint64_t WOLFSSL_OCSP_RESPONSE_IDENTIFIER;
typedef uint64_t WOLFSSL_OCSP_REQUEST_IDENTIFIER;


typedef WOLFSSL_SSL_IDENTIFIER SSL;
typedef WOLFSSL_SSL_CTX_IDENTIFIER SSL_CTX;
typedef WOLFSSL_X509_IDENTIFIER X509;
typedef WOLFSSL_X509_CTX_IDENTIFIER X509;
typedef WOLFSSL_DH_IDENTIFIER DH;
typedef WOLFSSL_EVP_PKEY_IDENTIFIER EVP_PKEY;
typedef WOLFSSL_SESSION_IDENTIFIER SSL_SESSION;
typedef WOLFSSL_BIO_IDENTIFIER BIO;
typedef WOLFSSL_509_STORE_IDENTIFIER X509_STORE;
typedef WOLFSSL_509_STORE_CTX_IDENTIFIER X509_STORE_CTX;
typedef WOLFSSL_EC_GROUP_IDENTIFIER EC_GROUP;
typedef WOLFSSL_OCSP_RESPONSE_IDENTIFIER OCSP_RESPONSE;
typedef WOLFSSL_OCSP_REQUEST_IDENTIFIER OCSP_REQUEST;


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