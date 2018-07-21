#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include "stdafx.h"
#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */

/* Use Debug SGX ? */
#if _DEBUG
	#define DEBUG_VALUE SGX_DEBUG_FLAG
#else
	#define DEBUG_VALUE 1
#endif

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

int main(int argc, char* argv[]) /* not using since just testing w/ wc_test */
{
	sgx_enclave_id_t id;
	sgx_launch_token_t t;

	int ret = 0;
	int sgxStatus = 0;
	int updated = 0;
    func_args args = { 0 };


    memset(t, 0, sizeof(sgx_launch_token_t));
    memset(&args,0,sizeof(args));

	ret = sgx_create_enclave(ENCLAVE_FILENAME, DEBUG_VALUE, &t, &updated, &id, NULL);
	if (ret != SGX_SUCCESS) {
		printf("Failed to create Enclave : error %d - %#x.\n", ret, ret);
		return 1;
	}    
    
    RsaKey rsakey;
    RNG rng;

    sgxStatus = enc_wc_InitRng(id,&ret,&rng);
    sgxStatus = enc_wc_InitRsaKey(id,&ret,&rsakey);
    printf("in here\n");
    sgxStatus = enc_wc_MakeRsaKey(id,&ret,&rsakey, 1024, 65537, &rng);

    //XMEMSET(&buf, 0, sizeof(buf));

    //wc_Sha256 sha;
    
    //char str[] = "abcdefghig";

    //sgxStatus = enc_hash256(id,&ret);
    //sgxStatus = enc_wc_Sha256(id, &ret, sha);
    //sgxStatus = enc_wc_Sha256Update(id, &ret, &sha, str, sizeof(str));
    
    
    //printf("%d",c);
    //c = enc_hash256(id,&ret);
    //printf("%d",c);
      




    return 0;
}















static double current_time()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);

	return (double)(1000000 * tv.tv_sec + tv.tv_usec)/1000000.0;
}

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */ printf("%s", str);
}

void ocall_current_time(double* time)
{
    if(!time) return;
    *time = current_time();
    return;
}

void ocall_low_res_time(int* time)
{
    struct timeval tv;
    if(!time) return;
    *time = tv.tv_sec;
    return;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
    return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}

