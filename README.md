# module_ssl_sgx
A port of the SSL module of Apache to Intel SGX. The performance penalty is around 90% of the normal module.

I highly recommend the use of my [custom OpenSSL Engine](https://github.com/andreluis034/sgx-keystore.openssl-engine) for the following reasons:
1. Almost no performance penalty relative to the normal implementation
2. Private keys are still kept private
3. Easier to keep the SSL module up to date
4. Not reliant on WolfSSL's compatability with OpenSSL

One big advantage of this version is that it keeps the TLS termination inside the enclave but it might not be relevant in most contexts because a malicious attacker with access to the machine can for example check the contents of the sent and receives messages on the read and write handles of Apache 
