#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <cpuid.h>
#include <immintrin.h>

#include <sfi.h>
#include "aes.h"

#define PASS_VAR volatile __attribute__((used))
#define PASS_FUNC __attribute__((used))

static char *crypt_simarea = NULL;
static char *crypt_simarea_iv = NULL;

PASS_VAR size_t sfi_cryptsim_size = 0;

void print_m128i(__m128i var)
{
    int64_t *v64val = (int64_t*) &var;
    printf("%.16lx %.16lx\n", v64val[1], v64val[0]);
}
void print_m256i(__m256i var)
{
    int64_t *v64val = (int64_t*) &var;
    printf("%.16lx %.16lx %.16lx %.16lx\n", v64val[3], v64val[2], v64val[1], v64val[0]);
}


/* Performs full CBC AES-128 encryption on a given area. Assumes the key is in
 * xmm register K0. */
void aes_cbc_enc(char *data, size_t len, char *iv)
{
    __m128i prevblock, tmp;
    size_t i;

    /* Populate all roundkey registers. */
    AES_KEYGEN_ALL(K0);

    /* Use IV for first iteration of CBC instead of previous block. */
    prevblock = _mm_load_si128((void*)iv);

    for (i = 0; i < len / 16; i++)
    {
        tmp = _mm_load_si128((void*)data);
        tmp = _mm_xor_si128(tmp, prevblock);
        XMM_FROM_VAR(XMM_SCRATCH, tmp);
        AES_ENCROUNDS(XMM_SCRATCH);
        XMM_TO_VAR(XMM_SCRATCH, prevblock);
        _mm_store_si128((void*)data, prevblock);
        data += 16;
    }
}

/* Performs full CBC AES-128 decryption on a given area. Assumes the key is in
 * xmm register K0. */
void aes_cbc_dec(char *data, size_t len, char *iv)
{
    __m128i prevblock, tmp, prevblock_crypt;
    size_t i;

    /* Populate all roundkey registers with decryption keys. */
    AES_KEYGEN_ALL(K0);
    AES_IMC_ALL();

    /* Use IV for first iteration of CBC instead of previous block. */
    prevblock = _mm_load_si128((void*)iv);

    for (i = 0; i < len / 16; i++)
    {
        /* Save ciphertext as we need it next round for XOR. */
        prevblock_crypt = _mm_load_si128((void*)data);
        XMM_FROM_VAR(XMM_SCRATCH, prevblock_crypt);
        AES_DECROUNDS(XMM_SCRATCH);
        XMM_TO_VAR(XMM_SCRATCH, tmp);
        tmp = _mm_xor_si128(tmp, prevblock);
        prevblock = prevblock_crypt;
        _mm_store_si128((void*)data, tmp);
        data += 16;
    }
}


void sfi_crypt_init()
{
    unsigned a, b, c, d;
    int i;

    __cpuid(1, a, b, c, d);
    assert((c & 0x2000000) && "CPU does not support AES extensions");
    __cpuid_count(7, 0, a, b, c, d);
    assert((b & (1 << 5)) && "CPU does not support AVX2 extensions");

    assert((sfi_cryptsim_size % 16) == 0);
    crypt_simarea = malloc(sfi_cryptsim_size);

    /* CBC needs an IV */
    crypt_simarea_iv = malloc(16);
    for (i = 0; i < 16; i++)
        crypt_simarea_iv[i] = i | (i << 4);

    /* Load a random key into the upper part of an YMM register, which should
     * never be touched by the normal application. */
    XMM_LOAD(XMM_SCRATCH, 0xdeadbeefdeadbeef, 0xcafebabecafebabe);
    YMM_UPPER_FROM_XMM(K, XMM_SCRATCH);

    /* Fill simarea with some data for debugging */
    for (i = 0; i < sfi_cryptsim_size; i++)
        crypt_simarea[i] = i % 256;

    /* Start the simarea off as encrypted until a domain needs it */
    YMM_UPPER_TO_XMM(K, K0);
    aes_cbc_enc(crypt_simarea, sfi_cryptsim_size, crypt_simarea_iv);

}
/* Encrypt data */
PASS_FUNC long sfi_crypt_begin_data(long data, void *addr)
{
    //printf("encdata %lx @ %p\n", data, addr);
    __m128i v;
    int64_t *v64val = (int64_t*) &v;

    XMM_LOAD(XMM_SCRATCH, addr, addr);

    AES_ENCROUNDS(XMM_SCRATCH);

    //XMM_LOAD(K, 0xdeadbeeffeebdaed, 0xcafebabecafebabe);
    //AES_ENCROUNDS_KEYGEN(XMM_SCRATCH, K, RK);

    //XMM_LOAD(RK, 0xdeadbeeffeebdaed, 0xcafebabecafebabe);
    //AES_ENCROUNDS_FAKERK(XMM_SCRATCH, RK);

    XMM_TO_VAR(XMM_SCRATCH, v);

    return data;
    return data ^ (uint64_t)v64val[0];
}
/* Decrypt data */
PASS_FUNC long sfi_crypt_end_data(long data, void *addr)
{
    //printf("decdata %lx @ %p\n", data, addr);
    __m128i v;
    int64_t *v64val = (int64_t*) &v;

    XMM_LOAD(XMM_SCRATCH, addr, addr);

    AES_ENCROUNDS(XMM_SCRATCH);

    //XMM_LOAD(K, 0xdeadbeeffeebdaed, 0xcafebabecafebabe);
    //AES_ENCROUNDS_KEYGEN(XMM_SCRATCH, K, RK);

    //XMM_LOAD(RK, 0xdeadbeeffeebdaed, 0xcafebabecafebabe);
    //AES_ENCROUNDS_FAKERK(XMM_SCRATCH, RK);

    XMM_TO_VAR(XMM_SCRATCH, v);

    return data;
    return data ^ (uint64_t)v64val[0];
}

/* Encrypt data array */
PASS_FUNC void sfi_crypt_memset(void *addr, size_t len, size_t elt_bits, uint64_t val)
{
    unsigned i;
    //printf("encmemset %p %zu %zu %lu\n", addr, len, elt_bits, val);
    if (elt_bits == 8)
    {
        uint8_t *p = addr;
        for (i = 0; i < len; i++)
            p[i] = (uint8_t)sfi_crypt_begin_data(val, &p[i]);
    }
    else if (elt_bits == 16)
    {
        uint16_t *p = addr;
        for (i = 0; i < len; i++)
            p[i] = (uint16_t)sfi_crypt_begin_data(val, &p[i]);
    }
    else if (elt_bits == 32)
    {
        uint32_t *p = addr;
        for (i = 0; i < len; i++)
            p[i] = (uint32_t)sfi_crypt_begin_data(val, &p[i]);
    }
    else if (elt_bits == 64)
    {
        uint64_t *p = addr;
        for (i = 0; i < len; i++)
            p[i] = (uint64_t)sfi_crypt_begin_data(val, &p[i]);
    }
}
PASS_FUNC void sfi_crypt_memcpy(void *dst, void *src, size_t len, size_t elt_bits)
{
    unsigned i;
    //printf("encmemcpy %p %p %zu %zu\n", dst, src, len, elt_bits);
    if (elt_bits == 8)
    {
        uint8_t *d = dst, *s = src;
        for (i = 0; i < len; i++)
            d[i] = (uint8_t)sfi_crypt_begin_data(sfi_crypt_begin_data(s[i], &s[i]), &d[i]);
    }
    else if (elt_bits == 16)
    {
        uint16_t *d = dst, *s = src;
        for (i = 0; i < len; i++)
            d[i] = (uint16_t)sfi_crypt_begin_data(sfi_crypt_begin_data(s[i], &s[i]), &d[i]);
    }
    else if (elt_bits == 32)
    {
        uint32_t *d = dst, *s = src;
        for (i = 0; i < len; i++)
            d[i] = (uint32_t)sfi_crypt_begin_data(sfi_crypt_begin_data(s[i], &s[i]), &d[i]);
    }
    else if (elt_bits == 64)
    {
        uint64_t *d = dst, *s = src;
        for (i = 0; i < len; i++)
            d[i] = (uint64_t)sfi_crypt_begin_data(sfi_crypt_begin_data(s[i], &s[i]), &d[i]);
    }
}

/* Entry to area needing the protected data - decrypt it in place. */
PASS_FUNC void sfi_crypt_begin(int domain)
{
    if (!crypt_simarea || !crypt_simarea_iv)
        return;
    YMM_UPPER_TO_XMM(K, K0);
    aes_cbc_dec(crypt_simarea, sfi_cryptsim_size, crypt_simarea_iv);
}

/* End of area needing the protected data - encrypt it again in place. */
PASS_FUNC void sfi_crypt_end(void)
{
    if (!crypt_simarea || !crypt_simarea_iv)
        return;
    YMM_UPPER_TO_XMM(K, K0);
    aes_cbc_enc(crypt_simarea, sfi_cryptsim_size, crypt_simarea_iv);
}
