#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/options.h>

#include "Wolfssl_Enclave_t.h"
#include <wolfssl/wolfcrypt/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>




#include "sgx_trts.h"


int enc_wc_InitRng(RNG* rng)
{       
    return wc_InitRng(&rng);
}

int enc_wc_InitRsaKey(RsaKey* rsakey)
{ 
    return  wc_InitRsaKey(&rsakey, 0);
}


int enc_wc_MakeRsaKey(RsaKey* rsakey, int size, long e, RNG* rng)
{
    return wc_MakeRsaKey(&rsakey, 1024, 65537, &rng);
}

    
    
    


int enc_wolfSSL_Cleanup(void)
{
    wolfSSL_Cleanup();
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return ret;
}

double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}
