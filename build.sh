#!/bin/bash

#build lib-enclave to have in-enclave sodium support
cd lib-enclave/Enclave
./patch_sodium.sh
cd ../
make ENCLAVE_TEST=1
#build ocaml_ctyppes
cd ../ocaml-ctypes
make
#build ocaml-sodium 
cd ../ocaml-sodium
make
make test_enclave



