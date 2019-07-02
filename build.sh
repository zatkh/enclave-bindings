#!/bin/bash

#build lib-enclave to have in-enclave sodium support
cd lib-enclave/Enclave
./patch_sodium.sh
cd ../
make ENCLAVE_TEST=1 
# for simulator mode when you don't have sgx support:
# make ENCLAVE_TEST=1 SGX_MODE=SIM

#build ocaml_ctyppes
cd ../ocaml-ctypes
make
#build ocaml-sodium 
cd ../ocaml-sodium
make
make test_enclave



