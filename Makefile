SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_PRERELEASE ?= 1
SGX_ARCH ?= x64
SGX_WOLFSSL_LIB ?=/home/andre/git/wolfssl/IDE/LINUX-SGX/
WOLFSSL_ROOT ?=/home/andre/git/wolfssl
SGX_SDK ?= /opt/intel/sgxsdk

ifndef WOLFSSL_ROOT
$(error WOLFSSL_ROOT is not set. Please set to root wolfssl directory)
endif



all:
	$(MAKE) -ef sgx_u.mk all SGX_SDK=$(SGX_SDK) SGX_WOLFSSL_LIB=$(SGX_WOLFSSL_LIB) WOLFSSL_ROOT=$(WOLFSSL_ROOT) SGX_MODE=$(SGX_MODE) SGX_PRERELEASE=$(SGX_PRERELEASE)
	$(MAKE) -ef sgx_t.mk all SGX_SDK=$(SGX_SDK) SGX_WOLFSSL_LIB=$(SGX_WOLFSSL_LIB) WOLFSSL_ROOT=$(WOLFSSL_ROOT) SGX_MODE=$(SGX_MODE) SGX_PRERELEASE=$(SGX_PRERELEASE)

install: all
	cp mod_example.so Enclave.signed.so /opt/httpd/modules

clean:
	$(MAKE) -ef sgx_u.mk clean
	$(MAKE) -ef sgx_t.mk clean

