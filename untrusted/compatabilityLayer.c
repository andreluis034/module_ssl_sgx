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