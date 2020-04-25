#include <wolfssl/ssl.h>

void sgx_ERR_error_string_n(unsigned long e, char* buf, unsigned long len)
{
	wolfSSL_ERR_error_string_n(e, buf, len);
}
unsigned long sgx_ERR_get_error()
{
	return wolfSSL_ERR_get_error();
}
void sgx_ERR_clear_error()
{
	wolfSSL_ERR_clear_error();
}


int sgx_ERR_GET_LIB(unsigned long err)
{
	return wolfSSL_ERR_GET_LIB(err);
}
int sgx_ERR_GET_REASON(unsigned long err)
{
	return wolfSSL_ERR_GET_REASON(err);
}
unsigned long sgx_ERR_peek_error()
{
	return wolfSSL_ERR_peek_error();
}