#ifndef WOLFSSL_ENCLAVE_U_H__
#define WOLFSSL_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

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

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_current_time, (double* time));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_low_res_time, (int* time));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recv, (int sockfd, void* buf, size_t len, int flags));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (int sockfd, const void* buf, size_t len, int flags));

sgx_status_t enc_wc_InitRng(sgx_enclave_id_t eid, int* retval, RNG* rng);
sgx_status_t enc_wc_InitRsaKey(sgx_enclave_id_t eid, int* retval, RsaKey* rsakey);
sgx_status_t enc_wc_MakeRsaKey(sgx_enclave_id_t eid, int* retval, RsaKey* key, int size, long int e, RNG* rng);
sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
