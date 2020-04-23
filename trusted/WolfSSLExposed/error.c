#include <wolfssl/ssl.h>

void sgx_ERR_error_string_n(unsigned long e, char* buf, unsigned long len)
{
	wolfSSL_ERR_error_string_n(e, buf, len);
}
unsigned long sgx_ERR_get_error()
{
	return wolfSSL_ERR_get_error();
}