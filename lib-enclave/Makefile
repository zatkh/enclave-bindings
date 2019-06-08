SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
EXE := main




all:
	$(MAKE) -f make_normal.mk all
	$(MAKE) -f make_enclave.mk all

clean:
	$(MAKE) -f make_normal.mk clean
	$(MAKE) -f make_enclave.mk clean

