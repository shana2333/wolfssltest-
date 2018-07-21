# How to run

set sdk environment
source /opt/intel/sgxsdk/environment


Compile

make -B SGX_MODE=SIM SGX_PRERELEASE=0 SGX_WOLFSSL_LIB=/home/shana/Desktop/wolfssl-3.14.0/IDE/LINUX-SGX/ WOLFSSL_ROOT=/home/shana/Desktop/wolfssl-3.14.0 

# Problem:undefined reference to `wc_MakeRsaKey'

/home/shana/Desktop/wolfssl-3.14.0/wolfssl/wolfcrypt/rsa.h:245:21: note: expected ‘WC_RNG * {aka struct WC_RNG *}’ but argument is of type ‘WC_RNG ** {aka struct WC_RNG **}’
     WOLFSSL_API int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng);
                     ^
CC  <=  trusted/Wolfssl_Enclave.c
-m64 -O2 -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L/opt/intel/sgxsdk/lib64 -L/home/shana/Desktop/wolfssl-3.14.0/IDE/LINUX-SGX/ -lwolfssl.sgx.static.lib -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--version-script=trusted/Wolfssl_Enclave.lds@
trusted/Wolfssl_Enclave.o: In function `enc_wc_MakeRsaKey':
Wolfssl_Enclave.c:(.text+0x60): undefined reference to `wc_MakeRsaKey'
collect2: error: ld returned 1 exit status
sgx_t.mk:131: recipe for target 'Wolfssl_Enclave.so' failed
make[1]: *** [Wolfssl_Enclave.so] Error 1
make[1]: Leaving directory '/home/shana/sgxcode/wolfsslsgxxx'
Makefile:13: recipe for target 'all' failed
make: *** [all] Error 2

