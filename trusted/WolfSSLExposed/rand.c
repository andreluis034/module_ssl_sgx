#include <wolfssl/ssl.h>

//NOTE: this doesn't actually do anything in wolfssl
int sgx_RAND_seed(char* seed, int len)
{
	return wolfSSL_RAND_seed(seed, len);
}
//Always returns success on WOLFSSL
int sgx_RAND_status()
{
	return wolfSSL_RAND_status();
}