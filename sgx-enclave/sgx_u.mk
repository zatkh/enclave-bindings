######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
ENCLAVE_DIR=enclave
SGX_BENCH ?=1
RESULT_DIR ?=results
RERUN ?=0
ifndef $(ITERATIONS)
ITERATIONS=1000
endif

CCBENHC_CFLAGS := -mtune=native -march=native -mssse3 -O3 -funroll-loops -DWITH_BARRIER -Wall


ifeq ($(SGX_BENCH), 1)
CCBENHC_CFLAGS += -DSGX_BENCHMARK 

endif

ifeq ($(RERUN), 0)
CCBENHC_CFLAGS += 

else
CCBENHC_CFLAGS += 
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

######## Untrusted Part Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Untrusted_C_Files := Untrusted/main.c Untrusted/ocalls.c #Untrusted/caches.c Untrusted/cctimer.c Untrusted/barrier.c Untrusted/cclfsr.c
Untrusted_Include_Paths := -IUntrusted -I$(SGX_SDK)/include -Iinclude

Untrusted_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Untrusted_Include_Paths) $(CCBENHC_CFLAGS)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Untrusted_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Untrusted_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Untrusted_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Untrusted_Cpp_Flags := $(Untrusted_C_Flags) -std=c++11
Untrusted_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -ldl

ifneq ($(SGX_MODE), HW)
	Untrusted_Link_Flags += -lsgx_uae_service_sim
else
	Untrusted_Link_Flags += -lsgx_uae_service
endif


Untrusted_Objects := $(Untrusted_C_Files:.c=.o) 

EXE := main



##### TARGETS #####

.PHONY: all run

# Default target "all" is to build
ifeq ($(Build_Mode), HW_RELEASE)
all: $(EXE)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(EXE) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(EXE) 
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

# Build and run project
run: all
ifneq ($(Build_Mode), HW_RELEASE)
	$(CURDIR)/$(EXE)
	@echo "RUN  =>  $(EXE) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## Untrusted Objects ########

# Genereate untrusted brigde routines (Enclave_u.c and Enclave_u.h) using .edl file
Untrusted/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd Untrusted && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

# Compile untrusted brigde routines
Untrusted/Enclave_u.o: Untrusted/Enclave_u.c
	$(CC) $(Untrusted_C_Flags) -DSGX_UNTRUSTED -c $< -o $@
	@echo "CC   <=  $<"

# Compile ocalls
Untrusted/ocalls.o: Untrusted/ocalls.c 
	$(CC) $(Untrusted_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Untrusted/main.o: Untrusted/ocalls.c 
	$(CC) $(Untrusted_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


Untrusted/%.o: Untrusted/%.c
	@$(CC) $(Untrusted_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


# Compile ocalls
Untrusted/main.o: Untrusted/main.c 
	$(CC) $(Untrusted_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


# Compile untrusted Untrustedlication
Untrusted/%.o: Untrusted/%.cpp
	$(CXX) $(Untrusted_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

# Link and generate main Untrustedlication executable
$(EXE): Untrusted/Enclave_u.o Untrusted/ocalls.o $(Untrusted_Objects)
	$(CXX) $^ -o $@ $(Untrusted_Link_Flags)
	@echo "LINK =>  $@"

.config_$(Build_Mode)_$(SGX_ARCH):
	rm -f .config_* $(EXE) $(Enclave_Name) $(Signed_Enclave_Name) $(Untrusted_Objects) Untrusted/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)


.PHONY: clean

clean:
	rm -f .config_* $(EXE) $(Untrusted_Objects) Untrusted/Enclave_u.*

