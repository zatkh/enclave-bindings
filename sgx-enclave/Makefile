SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
EXE := main


all:
	$(MAKE) -f sgx_u.mk all
	$(MAKE) -f sgx_t.mk all

clean:
	$(MAKE) -f sgx_u.mk clean
	$(MAKE) -f sgx_t.mk clean

