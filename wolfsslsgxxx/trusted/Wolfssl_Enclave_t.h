#ifndef WOLFSSL_ENCLAVE_T_H__
#define WOLFSSL_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"
#include "stdarg.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int enc_wc_InitRng(RNG* rng);
int enc_wc_InitRsaKey(RsaKey* rsakey);
int enc_wc_MakeRsaKey(RsaKey* key, int size, long int e, RNG* rng);
int enc_wolfSSL_Cleanup();

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_current_time(double* time);
sgx_status_t SGX_CDECL ocall_low_res_time(int* time);
sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
