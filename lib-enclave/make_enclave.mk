######## SGX Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
ENCLAVE_DIR=enclave
ENCLAVE_TEST ?=0
RESULT_DIR ?=results
RERUN ?=0
SODIUM := Enclave/libsodium-1.0.12/src/libsodium

ifndef $(ITERATIONS)
ITERATIONS=1000
endif





ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64 -fno-omit-frame-pointer
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g # Add debug symbols, turn off optimisations
else
        SGX_COMMON_CFLAGS += -O2 # turn on optimisations
endif


######## Enclave Settings ########


ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto




Enclave_Cpp_Files :=  
Enclave_C_Files := Enclave/Enclave.c Enclave/ocall_interface.c \
	$(SODIUM)/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c \
	$(SODIUM)/crypto_auth/crypto_auth.c\
	$(SODIUM)/crypto_auth/hmacsha256/auth_hmacsha256.c \
	$(SODIUM)/crypto_auth/hmacsha512/auth_hmacsha512.c \
	$(SODIUM)/crypto_auth/hmacsha512256/auth_hmacsha512256.c \
	$(SODIUM)/crypto_box/crypto_box.c \
	$(SODIUM)/crypto_box/crypto_box_easy.c \
	$(SODIUM)/crypto_box/crypto_box_seal.c \
	$(SODIUM)/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c \
	$(SODIUM)/crypto_core/curve25519/ref10/curve25519_ref10.c \
	$(SODIUM)/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c \
	$(SODIUM)/crypto_core/hsalsa20/core_hsalsa20.c \
	$(SODIUM)/crypto_core/salsa/ref/core_salsa_ref.c \
	$(SODIUM)/crypto_generichash/crypto_generichash.c \
	$(SODIUM)/crypto_generichash/blake2b/generichash_blake2.c \
	$(SODIUM)/crypto_generichash/blake2b/ref/blake2b-compress-ref.c \
	$(SODIUM)/crypto_generichash/blake2b/ref/blake2b-ref.c \
	$(SODIUM)/crypto_generichash/blake2b/ref/generichash_blake2b.c \
	$(SODIUM)/crypto_hash/crypto_hash.c \
	$(SODIUM)/crypto_hash/sha256/hash_sha256.c \
	$(SODIUM)/crypto_hash/sha256/cp/hash_sha256_cp.c \
	$(SODIUM)/crypto_hash/sha512/hash_sha512.c \
	$(SODIUM)/crypto_hash/sha512/cp/hash_sha512_cp.c \
	$(SODIUM)/crypto_onetimeauth/crypto_onetimeauth.c \
	$(SODIUM)/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c \
	$(SODIUM)/crypto_onetimeauth/poly1305/donna/poly1305_donna.c \
	$(SODIUM)/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c \
	$(SODIUM)/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c \
	$(SODIUM)/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c \
	$(SODIUM)/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c \
	$(SODIUM)/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c \
	$(SODIUM)/crypto_pwhash/crypto_pwhash.c \
	$(SODIUM)/crypto_pwhash/argon2/pwhash_argon2i.c \
	$(SODIUM)/crypto_pwhash/argon2/argon2.c \
	$(SODIUM)/crypto_pwhash/argon2/argon2-core.c \
	$(SODIUM)/crypto_pwhash/argon2/argon2-encoding.c \
	$(SODIUM)/crypto_pwhash/argon2/argon2-fill-block-ref.c \
	$(SODIUM)/crypto_pwhash/argon2/blake2b-long.c \
	$(SODIUM)/crypto_scalarmult/crypto_scalarmult.c \
	$(SODIUM)/crypto_scalarmult/curve25519/scalarmult_curve25519.c \
	$(SODIUM)/crypto_secretbox/crypto_secretbox.c \
	$(SODIUM)/crypto_secretbox/crypto_secretbox_easy.c \
	$(SODIUM)/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c \
	$(SODIUM)/crypto_shorthash/crypto_shorthash.c \
	$(SODIUM)/crypto_shorthash/siphash24/shorthash_siphash24.c \
	$(SODIUM)/crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c \
	$(SODIUM)/crypto_sign/crypto_sign.c \
	$(SODIUM)/crypto_sign/ed25519/sign_ed25519.c \
	$(SODIUM)/crypto_sign/ed25519/ref10/keypair.c \
	$(SODIUM)/crypto_sign/ed25519/ref10/open.c \
	$(SODIUM)/crypto_sign/ed25519/ref10/sign.c \
	$(SODIUM)/crypto_stream/crypto_stream.c \
	$(SODIUM)/crypto_stream/chacha20/stream_chacha20.c \
	$(SODIUM)/crypto_stream/chacha20/ref/chacha20_ref.c \
	$(SODIUM)/crypto_stream/salsa20/stream_salsa20.c \
	$(SODIUM)/crypto_stream/xsalsa20/stream_xsalsa20.c \
	$(SODIUM)/crypto_verify/sodium/verify.c \
	$(SODIUM)/randombytes/randombytes.c \
	$(SODIUM)/sodium/core.c \
	$(SODIUM)/sodium/runtime.c \
	$(SODIUM)/sodium/utils.c \
	$(SODIUM)/sodium/version.c \
	$(SODIUM)/crypto_scalarmult/curve25519/ref10/x25519_ref10.c \
	$(SODIUM)/crypto_stream/salsa20/ref/salsa20_ref.c \
	$(SODIUM)/randombytes/sysrandom/randombytes_sysrandom.c Enclave/nacl_runner.c



Enclave_Include_Paths := -Iinclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport 

Common_C_Cpp_Flags := -DOS_ID=1 $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fpic -fstack-protector -fno-builtin-printf -Wformat -Wformat-security -DSGX_ENCLAVE 

Enclave_C_Flags := $(Common_C_Cpp_Flags) $(Enclave_Include_Paths) -fno-omit-frame-pointer -g  $(CCBENHC_CFLAGS)
Enclave_C_Flags += -DCONFIGURED
Enclave_C_Flags += -I$(SODIUM)/include -I$(SODIUM)/include/sodium
Enclave_C_Flags += -DSGX



Enclave_Cpp_Flags := $(Common_C_Cpp_Flags) $(Enclave_C_Flags) -std=c++03 -nostdinc++ 
# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


EXE := main

.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(U_INTERFACE_Executable) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(U_INTERFACE_Executable)
	@echo "RUN  =>  $(U_INTERFACE_Executable) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif



######## Enclave Objects ########

# Genereate trusted brigde routines (Enclave_t.c and Enclave_t.h) using .edl file
Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

# Compile trusted brigde routines
Enclave/Enclave_t.o: Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

# Preprocess sqlite3
Enclave/ocall_interface.i: Enclave/ocall_interface.c
	$(CC) -I$(SGX_SDK)/include -E $< -o $@
	@echo "CC-Preprocess  <=  $<"

# Compile ocall_interface
Enclave/ocall_interface.o: Enclave/ocall_interface.i Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"


Enclave/%.o: Enclave/%.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects) $(Enclave_C_Objects) 
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags) 
	@echo "LINK =>  $@"


$(Signed_Enclave_Name): $(Enclave_Name)
	$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	rm -f $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_Cpp_Objects) Enclave/Enclave_t.* Enclave/ocall_interface.i $(Enclave_C_Objects)
