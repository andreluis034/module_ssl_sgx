#include <stdio.h>
#include "compatabilityHeader.h"
#include "Enclave_u.h"
extern sgx_enclave_id_t global_eid;    /* global enclave id */

int ERR_GET_LIB(unsigned long err)
{
	int ret; 
	sgx_ERR_GET_LIB(global_eid, &ret, err);
	return ret;
}
int ERR_GET_REASON(unsigned long err)
{
	int ret; 
	sgx_ERR_GET_REASON(global_eid, &ret, err);
	return ret;
}
unsigned long ERR_peek_error()
{
	unsigned long ret; 
	sgx_ERR_peek_error(global_eid, &ret);
	return ret;
}
static char error_string[256] = {0};
char* X509_verify_cert_error_string(long err)
{
	if (sgx_X509_verify_cert_error_string(global_eid, err, error_string, sizeof(error_string)) == SGX_SUCCESS)
	{
		return  error_string;
	}
	return NULL;	
}

#define PASSTHROUGH_FUNCTION__RET__0(returnType, name ) returnType name() \
{\
	returnType retVal; sgx_status_t status; \
	if((status = sgx_ ## name(global_eid, &retVal)) == SGX_SUCCESS) return retVal;	\
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); \
}
#define PASSTHROUGH_FUNCTION__RET__1(returnType, name, arg1Type ) returnType name(arg1Type arg1) \
{\
	returnType retVal; sgx_status_t status; \
	if((status = sgx_ ## name(global_eid, &retVal, arg1)) == SGX_SUCCESS) return retVal;	\
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); \
}
#define PASSTHROUGH_FUNCTION__RET__2(returnType, name, arg1Type, arg2Type ) returnType name(arg1Type arg1, arg2Type arg2) \
{\
	returnType retVal; sgx_status_t status; \
	if((status = sgx_ ## name(global_eid, &retVal, arg1, arg2)) == SGX_SUCCESS) return retVal;	\
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); \
}
#define PASSTHROUGH_FUNCTION__RET__3(returnType, name, arg1Type, arg2Type, arg3Type) returnType name(arg1Type arg1, arg2Type arg2, arg3Type arg3) \
{\
	returnType retVal; sgx_status_t status; \
	if((status = sgx_ ## name(global_eid, &retVal, arg1, arg2, arg3)) == SGX_SUCCESS) return retVal;	\
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); \
}
#define PASSTHROUGH_FUNCTION__RET__4(returnType, name, arg1Type, arg2Type, arg3Type, arg4Type ) returnType name(arg1Type arg1, arg2Type arg2, arg3Type arg3, arg4Type arg4) \
{\
	returnType retVal; sgx_status_t status; \
	if((status = sgx_ ## name(global_eid, &retVal, arg1, arg2, arg3, arg4)) == SGX_SUCCESS) return retVal;	\
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); \
}
#define PASSTHROUGH_FUNCTION__RET__5(returnType, name, arg1Type, arg2Type, arg3Type, arg4Type, arg5Type ) returnType name(arg1Type arg1, arg2Type arg2, arg3Type arg3, arg4Type arg4, arg5Type arg5) \
{\
	returnType retVal; sgx_status_t status; \
	if((status = sgx_ ## name(global_eid, &retVal, arg1, arg2, arg3, arg4, arg5)) == SGX_SUCCESS) return retVal;	\
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); \
}
#define PASSTHROUGH_FUNCTION4( name, arg1Type, arg2Type, arg3Type, arg4Type ) void name(arg1Type arg1, arg2Type arg2, arg3Type arg3, arg4Type arg4) \
{\
	sgx_status_t status; \
	if((status = sgx_ ## name(global_eid, arg1,arg2,arg3,arg4)) == SGX_SUCCESS) return;	\
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); \
}

#define PASSTHROUGH_FUNCTION1( name, arg1Type ) void name(arg1Type arg1) \
{\
	sgx_status_t status; \
	if((status = sgx_ ## name(global_eid, arg1)) == SGX_SUCCESS) return;	\
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); \
}

#define PASSTHROUGH_FUNCTION( name ) void name() \
{\
	sgx_status_t status; \
	if((status = sgx_ ## name(global_eid)) == SGX_SUCCESS) return;	\
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); \
}


const char* OpenSSL_version(int version)
{
    return LIBWOLFSSL_VERSION_STRING;
}

size_t SSL_get_peer_finished(SSL s, void *buf, size_t count)
{
	return WOLFSSL_FAILURE;
}

size_t SSL_get_finished(SSL s, void *buf, size_t count)
{
	return WOLFSSL_FAILURE;
}

unsigned int SSL_SESSION_get_compress_id(SSL_SESSION s)
{
	return 0;//NONE for wolfssl
}

uint8_t* SSL_SESSION_get_id(SSL_SESSION session, unsigned int* length)
{
	int _length;
	if (length == NULL)
		length = &_length;
	
	sgx_status_t status;
	if (sgx_SSL_SESSION_get_id_sz(global_eid, length, session) == SGX_SUCCESS && *length)
	{
		uint8_t* array = (uint8_t*) malloc(*length);
		if (array == NULL)
			return NULL;
		
		if (sgx_SSL_SESSION_get_id(global_eid, length, session, array, *length) == SGX_SUCCESS && *length)
		{
			return array;
		}

		free(array);
		return NULL;
		/* code */
	}
	return NULL;
	
}
PASSTHROUGH_FUNCTION__RET__1(X509, SSL_get_peer_certificate, SSL);
PASSTHROUGH_FUNCTION__RET__1(X509, SSL_get_certificate, SSL);
PASSTHROUGH_FUNCTION1(ASN1_OBJECT_free, ASN1_OBJECT);

PASSTHROUGH_FUNCTION__RET__1(int, SSL_session_reused, WOLFSSL_SSL_IDENTIFIER);
PASSTHROUGH_FUNCTION__RET__1(WOLFSSL_STACK_IDENTIFIER, SSL_get_peer_cert_chain, WOLFSSL_SSL_IDENTIFIER);
PASSTHROUGH_FUNCTION__RET__1(WOLFSSL_SSL_SESSION_IDENTIFIER, SSL_get_session, WOLFSSL_SSL_IDENTIFIER);

const char* SSL_get_version(WOLFSSL_SSL_IDENTIFIER ssl)
{
	char* allocated = (char*)malloc(256);
	if (allocated == NULL)
	{
		return "unknown";
	}
	
	sgx_status_t status; 
	int retVal;
	if((status = sgx_SSL_get_version(global_eid, &retVal, ssl, allocated, 256)) == SGX_SUCCESS && retVal)
	{
		if (strcmp(allocated, "TLSv1.1") == 0)
		{
			free(allocated);
			return "TLSv1.1";
		} 
		else if(strcmp(allocated,  "TLSv1.2") == 0)
		{
			free(allocated);
			return "TLSv1.2";
		}
		else
		{
			free(allocated);
			return "unknown";
		}
		
	}
	free(allocated);
	return "unknown";
}

//TODO this might not work for multiple servers?
static char server_name[256];
char * SSL_get_servername(WOLFSSL_SSL_IDENTIFIER ssl, uint8_t byte)
{
	sgx_status_t status; 
	int retVal;
	if((status = sgx_SSL_get_servername(global_eid, &retVal, ssl, byte, server_name, sizeof(server_name))) == SGX_SUCCESS && retVal)
	{
		return server_name;
	}
	return NULL;
}

PASSTHROUGH_FUNCTION1(X509_free, X509);
PASSTHROUGH_FUNCTION__RET__1(int, X509_up_ref, X509);
PASSTHROUGH_FUNCTION__RET__1(int, X509_get_signature_nid, X509_EXTENSION);
PASSTHROUGH_FUNCTION__RET__1(ASN1_STRING, X509_EXTENSION_get_data, X509_EXTENSION);

int X509_digest(X509 x509, EVP_MD digest, unsigned char* buffer, unsigned int* len)
{
	sgx_status_t status; 
	int written = 0;
	if((status = sgx_X509_digest(global_eid, &written, x509, digest, buffer, (size_t) *len)) == SGX_SUCCESS && written > 0)
	{
		*len = written;
	}
	return written;
}

char* X509_NAME_oneline(X509_NAME name, char* in, int sz)
{
	//TODO query the size of name
	if(in == NULL)
		in = malloc(sz == 0 ? 4096 : sz);
	sgx_status_t status; 
	int retVal = 0;
	if((status = sgx_X509_NAME_oneline(global_eid, &retVal, name, in, sz)) == SGX_SUCCESS && retVal)
	{
		return in;
	}
	return NULL;
}


PASSTHROUGH_FUNCTION__RET__1(EVP_MD, 	EVP_get_digestbynid, int);
PASSTHROUGH_FUNCTION__RET__0(EVP_MD,	EVP_md5);
PASSTHROUGH_FUNCTION__RET__0(EVP_MD,	EVP_sha1);
PASSTHROUGH_FUNCTION__RET__0(EVP_MD,	EVP_sha256);


PASSTHROUGH_FUNCTION__RET__0(BIO_METHOD, BIO_s_mem);
PASSTHROUGH_FUNCTION__RET__1(BIO, BIO_new, BIO_METHOD);
PASSTHROUGH_FUNCTION__RET__1(int, BIO_free, BIO);
PASSTHROUGH_FUNCTION__RET__3(int, BIO_read, BIO, void*, int);
PASSTHROUGH_FUNCTION__RET__1(int, BIO_pending, BIO );

PASSTHROUGH_FUNCTION__RET__4(int, X509_NAME_print_ex, BIO, X509_NAME, int, unsigned long);

int BIO_get_mem_ptr(BIO bio, BUF_MEM** mem)
{
	if(mem == NULL)
		return 0;
	int size;
	BUF_MEM* localMem = (BUF_MEM*)malloc(sizeof(BUF_MEM));
	if (sgx_BIO_get_mem_ptr(global_eid, &size, bio, NULL, 0) == SGX_SUCCESS && localMem->max)
	{
		localMem->length = localMem->max = size;
		localMem->data = (char*) malloc(localMem->length);
		sgx_BIO_get_mem_ptr(global_eid, &size, bio, localMem->data, localMem->length);
		localMem->length =  size;

		*mem = localMem;
		free(localMem);
		return localMem->length;
	}
	free(localMem);
	return 0;
}


PASSTHROUGH_FUNCTION1(BIO_vfree, BIO);
PASSTHROUGH_FUNCTION(ERR_clear_error);


PASSTHROUGH_FUNCTION__RET__4(int, X509V3_EXT_print, BIO, X509_EXTENSION, unsigned long, int);
PASSTHROUGH_FUNCTION__RET__1(ASN1_OBJECT, X509_EXTENSION_get_object, X509_EXTENSION);
PASSTHROUGH_FUNCTION__RET__2(int, OBJ_cmp, ASN1_OBJECT, ASN1_OBJECT);
PASSTHROUGH_FUNCTION__RET__2(ASN1_OBJECT, OBJ_txt2obj, const char*, int);
PASSTHROUGH_FUNCTION__RET__1(int, X509_get_ext_count, X509);
PASSTHROUGH_FUNCTION__RET__1(ASN1_TIME, X509_get_notBefore, X509);
PASSTHROUGH_FUNCTION__RET__1(ASN1_TIME, X509_get_notAfter, X509);
PASSTHROUGH_FUNCTION__RET__1(X509_NAME, X509_get_subject_name, X509);
PASSTHROUGH_FUNCTION__RET__1(X509_NAME, X509_get_issuer_name, X509);
PASSTHROUGH_FUNCTION__RET__2(X509_NAME_ENTRY, X509_NAME_get_entry, X509_NAME, int);
PASSTHROUGH_FUNCTION__RET__1(int, OBJ_obj2nid, ASN1_OBJECT);
PASSTHROUGH_FUNCTION__RET__2(int, ASN1_TIME_print, BIO, ASN1_TIME);
PASSTHROUGH_FUNCTION__RET__2(int, i2a_ASN1_INTEGER, BIO, ASN1_INTEGER);
PASSTHROUGH_FUNCTION__RET__1(BIGNUM, ASN1_INTEGER_to_BN, ASN1_INTEGER);
PASSTHROUGH_FUNCTION__RET__1(ASN1_INTEGER, X509_get_serialNumber, X509);
PASSTHROUGH_FUNCTION__RET__1(long, SSL_get_verify_result, SSL);

PASSTHROUGH_FUNCTION1(ASN1_STRING_free, ASN1_STRING);
PASSTHROUGH_FUNCTION__RET__2(int, SSL_CIPHER_get_bits, SSL_CIPHER, int*);
PASSTHROUGH_FUNCTION__RET__1(SSL_CIPHER, SSL_get_current_cipher, SSL);


		//int sgx_SSL_CIPHER_get_name(WOLFSSL_SSL_CIPHER_IDENTIFIER cipherId, [out, size=length] char* buffer, int length);

#define BUFFER_SIZE 256
char SSL_CIPHER_get_name_buffer[BUFFER_SIZE];
char* SSL_CIPHER_get_name(SSL_CIPHER cipher)
{
	int retVal = 0;
	sgx_status_t status; 
	if((status = sgx_SSL_CIPHER_get_name(global_eid, &retVal, cipher, SSL_CIPHER_get_name_buffer, BUFFER_SIZE)) == SGX_SUCCESS) 
	{
		if (retVal)
		{
			return SSL_CIPHER_get_name_buffer;
		}
		return "Unknown_not_enough_memory_for_SSL_CIPHER_get_name";
		
	}


	printf("[-] Call to %s failed: 0x%X\n", __func__, status); 
}
PASSTHROUGH_FUNCTION1(BN_free, BIGNUM);

PASSTHROUGH_FUNCTION__RET__2(X509_EXTENSION, X509_get_ext, X509, int);
PASSTHROUGH_FUNCTION__RET__1(long, X509_get_version, X509);
PASSTHROUGH_FUNCTION4( X509_ALGOR_get0, ASN1_OBJECT*, int *, const void**, X509_ALGOR);
PASSTHROUGH_FUNCTION__RET__1(X509_ALGOR, X509_get0_tbs_sigalg, X509);
PASSTHROUGH_FUNCTION__RET__1(X509_PUBKEY, X509_get_X509_PUBKEY, X509);
PASSTHROUGH_FUNCTION__RET__1(int, X509_NAME_entry_count, X509_NAME);
PASSTHROUGH_FUNCTION__RET__5(int, X509_PUBKEY_get0_param, ASN1_OBJECT*, const unsigned char **, int *, void **, X509_PUBKEY);
PASSTHROUGH_FUNCTION__RET__1(ASN1_OBJECT, X509_NAME_ENTRY_get_object, X509_NAME_ENTRY);

PASSTHROUGH_FUNCTION__RET__1(int, sk_X509_num, SSL_STACK);
PASSTHROUGH_FUNCTION__RET__2(X509, sk_X509_value, SSL_STACK, int);
PASSTHROUGH_FUNCTION__RET__2(int, PEM_write_bio_X509, BIO, X509);

char* BN_bn2dec(BIGNUM bn)
{
	int retVal = 0;
	sgx_status_t status; 
	sgx_BN_bn2dec(global_eid, &retVal, bn, NULL, 0);
	if((status = sgx_BN_bn2dec(global_eid, &retVal, bn, NULL, 0)) == SGX_SUCCESS) 
	{
		if (retVal == 0)
			return NULL;
		char * buffer = (char*)malloc(retVal + 1);		
		if(buffer == NULL)
			return NULL;
		if((status = sgx_BN_bn2dec(global_eid, &retVal, bn, buffer, retVal + 1)) == SGX_SUCCESS)
		{
			return buffer;
		}
		printf("[-] 2nd Call to %s failed: 0x%X\n", __func__, status); 
		free(buffer);
		return NULL;
	}
	printf("[-] Call to %s failed: 0x%X\n", __func__, status); 
}
char OBJ_nid2ln_buffer[BUFFER_SIZE];
char* OBJ_nid2ln(int n)
{
	int retVal = 0;
	sgx_status_t status; 
	if((status = sgx_OBJ_nid2ln(global_eid, &retVal, n, OBJ_nid2ln_buffer, BUFFER_SIZE)) == SGX_SUCCESS) 
	{
		if (retVal)
		{
			return OBJ_nid2ln_buffer;
		}
		return NULL;
		
	}


	printf("[-] Call to %s failed: 0x%X\n", __func__, status); 
}