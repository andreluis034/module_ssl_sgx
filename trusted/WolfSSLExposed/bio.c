#include "maps.h"
#include <sgx_trts.h>
#include "../util_defs.h"
#include "../Enclave_t.h"


#define CALLBACK_PRELUDE(index) 	WOLFSSL_BIO_IDENTIFIER bioId = MAP_GET(WolfBioMapInverse, bio);\
	if(bioId == INVALID_IDENTIFIER)\
	{\
		printf("[ERROR][%s] Could not obtain bio identifier from pointer\n", __func__);\
		return 0;\
	}\
	WOLFSSL_BIO_METHOD* biom = bio->method;\
	\
	void** array = GetBioCallbackArray(biom);\
	if(array == NULL)\
	{\
		printf("[ERROR][%s]Got null callback array\n");\
		return 0;\
	} \
	if(array[index] == NULL)\
	{\
		printf("[ERROR][%s]Got null function pointer\n");\
		return 0;\
	}\


#define CALLBACK_REGISTER(methodName, index) int sgx_ ## methodName(WOLFSSL_BIO_METHOD_IDENTIFIER biomId, void* callback) {\
	WOLFSSL_BIO_METHOD* biom = MAP_GET(WolfBioMethodMap, biomId); \
	if(biom == NULL || callback == NULL) return WOLFSSL_FAILURE; \
	void ** array = CreateBioCallbackArray(biom); \
	array[BIO_WRITE_CALLBACK_INDEX] = callback; \
	return wolfSSL_ ## methodName(biom, &methodName ## _callback_handler); \
	}

#define GET_BIO(var_name, id, default_return_value) WOLFSSL_BIO* var_name =  WolfBioMapTypeGet(&WolfBioMap, id); if(var_name == NULL) return default_return_value

#define BIO_CALLBACK_COUNT 7
enum 
{
	BIO_WRITE_CALLBACK_INDEX = 0,
	BIO_READ_CALLBACK_INDEX = 1,
	BIO_PUTS_CALLBACK_INDEX = 2,
	BIO_GETS_CALLBACK_INDEX = 3,
	BIO_CTRL_CALLBACK_INDEX = 4,
	BIO_CREATE_CALLBACK_INDEX = 5,
	BIO_DESTROY_CALLBACK_INDEX = 6,
};

void** GetBioCallbackArray(WOLFSSL_BIO_METHOD* biom);
void DeleteCallbackArrayFromBio(WOLFSSL_BIO* bio);
void DeleteCallbackArrayFromBiom(WOLFSSL_BIO_METHOD* biom);

void** CreateBioCallbackArray(WOLFSSL_BIO_METHOD* biom);



WOLFSSL_BIO_IDENTIFIER sgx_BIO_new_file(const char *filename, const char *mode)
{
	uint64_t filePtr;
	int len;
	char buffer[1024];
	if(strcmp(mode, "r") != 0)
		return 0; //Only read implemented


	//sgx_status_t SGX_CDECL ocall_fopen(uint64_t* retval, const char* file, const char* mode)

	ocall_fopen(&filePtr, filename, mode);
	if(filePtr == 0)	return 0;

	WOLFSSL_BIO*  bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());//wolfSSL_BIO_new_file(filename, mode);


	ocall_fread(&len, buffer, 1, sizeof(buffer), filePtr);

	while(len > 0 )
	{
		wolfSSL_BIO_write(bio, buffer, len);
		len = 0;
		ocall_fread(&len, buffer, 1, sizeof(buffer), filePtr);
	}
	ocall_fclose(filePtr);

	WOLFSSL_BIO_IDENTIFIER bioId = 0;
	RandomUntilNonExistant(bioId, WolfBioMap);

	WolfBioMapTypeAdd		(&WolfBioMap, bioId, bio);
	WolfBioMapInverseTypeAdd(&WolfBioMapInverse, bio, bioId);

	return bioId;
}


WOLFSSL_BIO_IDENTIFIER sgx_BIO_new(WOLFSSL_BIO_METHOD_IDENTIFIER methodId)
{
	WOLFSSL_BIO_METHOD* bioMethod = MAP_GET(WolfBioMethodMap, methodId);// GetBioMethod((enum BIO_TYPE)methodId);
	if(bioMethod == NULL)
	{
		return 0;
	}
	WOLFSSL_BIO*  bio  =  wolfSSL_BIO_new(bioMethod);
	WOLFSSL_BIO_IDENTIFIER bioId = 0;
	RandomUntilNonExistant(bioId, WolfBioMap);
	WolfBioMapTypeAdd		(&WolfBioMap, bioId, bio);
	WolfBioMapInverseTypeAdd(&WolfBioMapInverse, bio, bioId);

	return bioId;
}

WOLFSSL_BIO_IDENTIFIER sgx_BIO_push(WOLFSSL_BIO_IDENTIFIER bioId1, WOLFSSL_BIO_IDENTIFIER bioId2)
{
	WOLFSSL_BIO* bio1 = WolfBioMapTypeGet(&WolfBioMap, bioId1);
	WOLFSSL_BIO* bio2 = WolfBioMapTypeGet(&WolfBioMap, bioId2);
	
	if(bio1 == NULL || bio2 == NULL) return INVALID_IDENTIFIER;

	WOLFSSL_BIO* bio3 = wolfSSL_BIO_push(bio1, bio2);

	WOLFSSL_BIO_IDENTIFIER retBioId  = WolfBioMapInverseTypeGet(&WolfBioMapInverse, bio3);
	
	if (retBioId) return retBioId;

	RandomUntilNonExistant(retBioId, WolfBioMap);
	WolfBioMapTypeAdd		(&WolfBioMap, retBioId, bio3);
	WolfBioMapInverseTypeAdd(&WolfBioMapInverse, bio3, retBioId);

	return retBioId;
}

WOLFSSL_EVP_PKEY_IDENTIFIER sgx_d2i_PrivateKey_bio(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = WolfBioMapTypeGet(&WolfBioMap, bioId);
	if(bio == NULL) return INVALID_IDENTIFIER;

	WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PrivateKey_bio(bio, NULL);

	WOLFSSL_EVP_PKEY_IDENTIFIER keyId = 0;
	
	RandomUntilNonExistant		(keyId, WolfEvpPkeyMap);
	WolfEvpPkeyMapTypeAdd		(&WolfEvpPkeyMap, 			keyId, pkey);
	WolfEvpPkeyMapInverseTypeAdd(&WolfEvpPkeyMapInverse, 	pkey, keyId);
}
void sgx_BIO_meth_free(WOLFSSL_BIO_METHOD_IDENTIFIER biomId)
{
	WOLFSSL_BIO_METHOD* biom = MAP_GET(WolfBioMethodMap, biomId);
	if(biom == NULL)
	{
		printf("[WARNING][%s]Failed to get WOLFSSL_BIO_METHOD with id 0x%X", __func__, biomId);
		return;
	}
	MAP_REMOVE_TWO_WAY(WolfBioMethodMap, biomId, biom);
	wolfSSL_BIO_meth_free(biom);
	DeleteCallbackArrayFromBiom(biom);
}

int sgx_BIO_free(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = WolfBioMapTypeGet(&WolfBioMap, bioId);
	if(bio == NULL)
	{
		return 0;
	}

	WolfBioMapTypeRemove(&WolfBioMap, bioId);
	WolfBioMapInverseTypeRemove(&WolfBioMapInverse, bio);
	int result =  wolfSSL_BIO_free(bio);
	DeleteCallbackArrayFromBio(bio);
	return result;
}

int sgx_BIO_free_all(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = WolfBioMapTypeGet(&WolfBioMap, bioId);
    while (bio) {
		bioId = WolfBioMapInverseTypeGet(&WolfBioMapInverse, bio);

        WOLFSSL_BIO* next = bio->next;
		sgx_BIO_free(bioId);
		//wolfSSL_BIO_free(bio);
        bio = next;
    }
    return 0;

}

static WOLFSSL_BIO_METHOD_IDENTIFIER base64Id = 0;
WOLFSSL_BIO_METHOD_IDENTIFIER sgx_BIO_f_base64()
{
	if(base64Id == 0)
	{
		InsertInMapTwoWay(base64Id, wolfSSL_BIO_f_base64(), WolfBioMethodMap);
	}
	return base64Id;
}
static WOLFSSL_BIO_METHOD_IDENTIFIER memId = 0;
WOLFSSL_BIO_METHOD_IDENTIFIER sgx_BIO_s_mem()
{
	if(memId == 0)
	{
		InsertInMapTwoWay(memId, wolfSSL_BIO_f_base64(), WolfBioMethodMap);
	}
	return memId;
}

int sgx_BIO_flush(WOLFSSL_BIO_IDENTIFIER bioId)
{
	GET_BIO(bio, bioId, 0);

	return wolfSSL_BIO_flush(bio);
}

int sgx_BIO_pending(WOLFSSL_BIO_IDENTIFIER bioId)
{
	GET_BIO(bio, bioId, 0);

	return wolfSSL_BIO_pending(bio);
}


int sgx_BIO_read(WOLFSSL_BIO_IDENTIFIER bioId, void* buffer, size_t len)
{
	GET_BIO(bio, bioId, 0);

	return wolfSSL_BIO_read(bio, buffer, len);
}


int sgx_BIO_puts(WOLFSSL_BIO_IDENTIFIER bioId, const char *buf)
{
	GET_BIO(bio, bioId, 0);

	return wolfSSL_BIO_puts(bio, buf);
}


//NOTE: These do nothing in WolfSSL
void sgx_BIO_set_shutdown(WOLFSSL_BIO_IDENTIFIER bioId, int shut)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	 	return;

	wolfSSL_BIO_set_shutdown(bio, shut);
}

long 	sgx_BIO_get_shutdown(WOLFSSL_BIO_IDENTIFIER bioId)
{
	GET_BIO(bio, bioId, 0);

	return wolfSSL_BIO_get_shutdown(bio);
	
}

void sgx_BIO_set_init(WOLFSSL_BIO_IDENTIFIER bioId, int i)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	 	return;
	
	wolfSSL_BIO_set_init(bio, i);
}


void sgx_BIO_clear_retry_flags(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	 	return;
	
	wolfSSL_BIO_clear_retry_flags(bio);
}


//This value will only be stored and not actually used inside sgx so we can skip verification steps regarding pointer check
void sgx_BIO_set_data(WOLFSSL_BIO_IDENTIFIER bioId, void* ptr)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	 	return;

	wolfSSL_BIO_set_data(bio, ptr);
}

void* sgx_BIO_get_data(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	 	return NULL;

	return wolfSSL_BIO_get_data(bio);
}


//BIO callbacks

void** GetBioCallbackArray(WOLFSSL_BIO_METHOD* biom)
{
	if (biom == NULL)
		return NULL;
	
	return MAP_GET(WolfBioCallbackMap, biom);
}

void** CreateBioCallbackArray(WOLFSSL_BIO_METHOD* biom)
{
	if (biom == NULL)
	{
		return NULL;
	}
	void** array = GetBioCallbackArray(biom);
	if(array != NULL)
		return array;
	array = malloc(sizeof(void*) * BIO_CALLBACK_COUNT);
	memset(array, 0, sizeof(void*) * BIO_CALLBACK_COUNT);
	MAP_INSERT(WolfBioCallbackMap, biom, array);
	return array;
}

void DeleteCallbackArrayFromBio(WOLFSSL_BIO* bio)
{
	DeleteCallbackArrayFromBiom(bio->method);
}


void DeleteCallbackArrayFromBiom(WOLFSSL_BIO_METHOD* biom)
{
	void **array = GetBioCallbackArray(biom);
	if(array == NULL || biom == NULL)
		return;
	MAP_REMOVE(WolfBioCallbackMap, biom);
	free(array);
}

int BIO_meth_set_write_callback_handler(WOLFSSL_BIO *bio, const char *in, int inl)
{
	CALLBACK_PRELUDE(BIO_WRITE_CALLBACK_INDEX);
	int retval = 0;
	do_BIO_meth_write_cb(&retval, bioId, in, inl, array[BIO_WRITE_CALLBACK_INDEX]);
	return retval;
}

int BIO_meth_set_read_callback_handler(WOLFSSL_BIO *bio, char *in, int inl)
{
	CALLBACK_PRELUDE(BIO_READ_CALLBACK_INDEX);
	int retval = 0;
	do_BIO_meth_read_cb(&retval, bioId, in, inl, array[BIO_READ_CALLBACK_INDEX]);
	return retval;
}

int BIO_meth_set_puts_callback_handler(WOLFSSL_BIO *bio, const char *in)
{
	CALLBACK_PRELUDE(BIO_PUTS_CALLBACK_INDEX);
	int retval = 0;
	do_BIO_meth_puts_cb(&retval, bioId, in, array[BIO_PUTS_CALLBACK_INDEX]);
	return retval;
}
int BIO_meth_set_gets_callback_handler(WOLFSSL_BIO *bio, char *in, int inl)
{
	CALLBACK_PRELUDE(BIO_GETS_CALLBACK_INDEX);
	int retval = 0;
	do_BIO_meth_gets_cb(&retval, bioId, in, inl, array[BIO_GETS_CALLBACK_INDEX]);
	return retval;
}

long BIO_meth_set_ctrl_callback_handler(WOLFSSL_BIO* bio, int cmd, long num, void* ptr)
{
	CALLBACK_PRELUDE(BIO_CTRL_CALLBACK_INDEX);
	long retval = 0;
	do_BIO_meth_ctrl_cb(&retval, bioId, cmd, num, array[BIO_CTRL_CALLBACK_INDEX]); //TODO PTR seems ignored by apachge?
	return retval;
}

int BIO_meth_set_create_callback_handler(WOLFSSL_BIO* bio)
{
	CALLBACK_PRELUDE(BIO_CREATE_CALLBACK_INDEX);
	int retval = 0;
	do_BIO_meth_create_cb(&retval, bioId, array[BIO_CREATE_CALLBACK_INDEX]);
	return retval;
}

int BIO_meth_set_destroy_callback_handler(WOLFSSL_BIO* bio)
{
	CALLBACK_PRELUDE(BIO_DESTROY_CALLBACK_INDEX);
	int retval = 0;
	do_BIO_meth_destroy_cb(&retval, bioId, array[BIO_DESTROY_CALLBACK_INDEX]);
	return retval;
}


CALLBACK_REGISTER(BIO_meth_set_write, 	BIO_WRITE_CALLBACK_INDEX)
CALLBACK_REGISTER(BIO_meth_set_read, 	BIO_READ_CALLBACK_INDEX)
CALLBACK_REGISTER(BIO_meth_set_puts, 	BIO_PUTS_CALLBACK_INDEX)
CALLBACK_REGISTER(BIO_meth_set_gets, 	BIO_GETS_CALLBACK_INDEX)
CALLBACK_REGISTER(BIO_meth_set_ctrl, 	BIO_CTRL_CALLBACK_INDEX)
CALLBACK_REGISTER(BIO_meth_set_create, 	BIO_CREATE_CALLBACK_INDEX)
CALLBACK_REGISTER(BIO_meth_set_destroy, BIO_DESTROY_CALLBACK_INDEX)

void sgx_BIO_set_callback_arg(WOLFSSL_BIO_IDENTIFIER bioId, void* data)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant bioId 0x%X", __func__, bioId);
	 	return ;
	}
	wolfSSL_BIO_set_callback_arg(bio, data);
}

void* sgx_BIO_get_callback_arg(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant bioId 0x%X", __func__, bioId);
	 	return NULL;
	}
	return wolfSSL_BIO_get_callback_arg(bio);
}

long sgx_BIO_set_nbio(WOLFSSL_BIO_IDENTIFIER bioId, long on)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant bioId 0x%X", __func__, bioId);
	 	return 1;
	}
	return wolfSSL_BIO_set_nbio(bio, on);
}


void sgx_BIO_set_retry_read(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant bioId 0x%X", __func__, bioId);
	 	return;
	}
	wolfSSL_BIO_set_flags(bio, WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_READ);
}
void sgx_BIO_set_retry_write(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant bioId 0x%X", __func__, bioId);
	 	return;
	}
	wolfSSL_BIO_set_flags(bio, WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_WRITE);
}


WOLFSSL_BIO_METHOD_IDENTIFIER sgx_SSL_BIO_meth_new(int type, const char *name)
{
	WOLFSSL_BIO_METHOD* biom = wolfSSL_BIO_meth_new(type, name);
	if(biom == NULL)
		return INVALID_IDENTIFIER;
	
	CheckExistingOrCreate(WOLFSSL_BIO_METHOD_IDENTIFIER, biomId, biom, WolfBioMethodMap);

	return biomId;
}

long BIO_set_callback_handler(WOLFSSL_BIO* bio, int event, const char* parg, int iarg, long larg, long return_value)
{
	WOLFSSL_BIO_IDENTIFIER bioId = MAP_GET(WolfBioMapInverse, bio);
	if (bioId == INVALID_IDENTIFIER)
	{
		printf("[WARN][%s] Attempt to get non-existant bio %p", __func__, bio);
		return WOLFSSL_FAILURE;
	}
	void* callback = MAP_GET(WolfBioCallbackMap2, bio);
	if (callback == NULL)
	{
		printf("[WARN][%s] Callback from bio %p is a null pointer", __func__, bio);
		return WOLFSSL_FAILURE;
	}
	
	long ret;
	do_BIO_info_cb(&ret, bioId,  event, parg, iarg, larg, return_value, callback);

	return ret;
}


void sgx_BIO_set_callback(WOLFSSL_BIO_IDENTIFIER bioId, void* callback)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant bioId 0x%X", __func__, bioId);
	 	return;
	}
	if (callback == NULL)
	{
		wolfSSL_BIO_set_callback(bio, NULL);
		return;
	}
	if(MAP_GET(WolfBioCallbackMap2, bio))
	{
		wolfSSL_BIO_set_callback(bio, NULL);
		MAP_REMOVE(WolfBioCallbackMap2, bio);
	}
	MAP_INSERT(WolfBioCallbackMap2, bio, callback);	
	wolfSSL_BIO_set_callback(bio, BIO_set_callback_handler );
}


int sgx_BIO_get_mem_ptr(WOLFSSL_BIO_IDENTIFIER bioId, uint8_t* buffer, unsigned int buffer_len)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant bioId 0x%X", __func__, bioId);
	 	return 0;
	}
	BUF_MEM* mem = NULL;
	if(wolfSSL_BIO_get_mem_ptr(bio, &mem) == WOLFSSL_FAILURE)
	{
		return WOLFSSL_FAILURE;
	}
	if(buffer == NULL || buffer_len == 0)
	{
		return mem->length;
	}
	if(mem->length > buffer_len)
	{
		return WOLFSSL_FAILURE;
	}

	memcpy(buffer, mem->data, mem->length);
	return mem->length;	
}


void sgx_BIO_vfree(WOLFSSL_BIO_IDENTIFIER bioId)
{
	WOLFSSL_BIO* bio = MAP_GET(WolfBioMap, bioId);
	if(bio == NULL)
	{
		printf("[WARN][%s] Attempt to get non-existant bioId 0x%X", __func__, bioId);
	 	return;
	}
	BIO_vfree(bio);
}


