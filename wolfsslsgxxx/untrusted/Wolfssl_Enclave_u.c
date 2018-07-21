#include "Wolfssl_Enclave_u.h"
#include <errno.h>

typedef struct ms_enc_wc_InitRng_t {
	int ms_retval;
	RNG* ms_rng;
} ms_enc_wc_InitRng_t;

typedef struct ms_enc_wc_InitRsaKey_t {
	int ms_retval;
	RsaKey* ms_rsakey;
} ms_enc_wc_InitRsaKey_t;

typedef struct ms_enc_wc_MakeRsaKey_t {
	int ms_retval;
	RsaKey* ms_key;
	int ms_size;
	long int ms_e;
	RNG* ms_rng;
} ms_enc_wc_MakeRsaKey_t;

typedef struct ms_enc_wolfSSL_Cleanup_t {
	int ms_retval;
} ms_enc_wolfSSL_Cleanup_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_current_time_t {
	double* ms_time;
} ms_ocall_current_time_t;

typedef struct ms_ocall_low_res_time_t {
	int* ms_time;
} ms_ocall_low_res_time_t;

typedef struct ms_ocall_recv_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_current_time(void* pms)
{
	ms_ocall_current_time_t* ms = SGX_CAST(ms_ocall_current_time_t*, pms);
	ocall_current_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_low_res_time(void* pms)
{
	ms_ocall_low_res_time_t* ms = SGX_CAST(ms_ocall_low_res_time_t*, pms);
	ocall_low_res_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, (const void*)ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_Wolfssl_Enclave = {
	5,
	{
		(void*)Wolfssl_Enclave_ocall_print_string,
		(void*)Wolfssl_Enclave_ocall_current_time,
		(void*)Wolfssl_Enclave_ocall_low_res_time,
		(void*)Wolfssl_Enclave_ocall_recv,
		(void*)Wolfssl_Enclave_ocall_send,
	}
};
sgx_status_t enc_wc_InitRng(sgx_enclave_id_t eid, int* retval, RNG* rng)
{
	sgx_status_t status;
	ms_enc_wc_InitRng_t ms;
	ms.ms_rng = rng;
	status = sgx_ecall(eid, 0, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wc_InitRsaKey(sgx_enclave_id_t eid, int* retval, RsaKey* rsakey)
{
	sgx_status_t status;
	ms_enc_wc_InitRsaKey_t ms;
	ms.ms_rsakey = rsakey;
	status = sgx_ecall(eid, 1, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wc_MakeRsaKey(sgx_enclave_id_t eid, int* retval, RsaKey* key, int size, long int e, RNG* rng)
{
	sgx_status_t status;
	ms_enc_wc_MakeRsaKey_t ms;
	ms.ms_key = key;
	ms.ms_size = size;
	ms.ms_e = e;
	ms.ms_rng = rng;
	status = sgx_ecall(eid, 2, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Cleanup_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

