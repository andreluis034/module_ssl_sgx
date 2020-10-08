# module_ssl_sgx
A port of the SSL module of Apache to Intel SGX. The performance penalty is around 90% of the normal module.

I highly recommend the use of my [custom OpenSSL Engine](https://github.com/andreluis034/sgx-keystore.openssl-engine) for the following reasons:
1. Almost no performance penalty relative to the normal implementation
2. Private keys are still kept private
3. Easier to keep the SSL module up to date
4. Not limited to a single process
5. Not reliant on WolfSSL's compatability with OpenSSL

One big advantage of this version is that it keeps the TLS termination inside the enclave but it might not be relevant in most contexts because a malicious attacker with access to the machine can for example check the contents of the sent and receives messages on the read and write handles of Apache 

### Requirements
* An Intel SGX capable CPU
* [Intel(R) Software Guard Extensions for Linux* OS](https://github.com/intel/linux-sgx)
* [WolfSSL compiled for SGX](https://github.com/wolfSSL/wolfssl/tree/9a1687d00e0286b52253c434221257c808369dc6/IDE/LINUX-SGX)
* [Patch WolfSSL with the following changes](https://github.com/andreluis034/module_ssl_sgx/blob/master/WolfSSL.patch)
* OpenSSL 1.1+ 

### How to build
1. Download and Compile WolfSSL for SGX with supplied changes
2. Set WolfSSL_ROOT to the root of WolfSSL folder
3. Edit `Apache_Include_Paths` in the file `sgx_u.mk` so that it points to the include dir of Apache. 
4. Run `make` in the root of this git
5. Copy the `mod_ssl_sgx.so` binary to the modules folder in apache
6. Copy the enclave file `Enclave.signed.so` to the same folder as the apache binary 
