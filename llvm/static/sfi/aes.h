#ifndef _SFI_AES_H
#define _SFI_AES_H

/* What xmm registers to use for what */
// for on-the-fly RK keygen
#define K "15"
#define RK "14"
// for perma-store all RKs
#define K0 "5"
#define K1 "6"
#define K2 "7"
#define K3 "8"
#define K4 "9"
#define K5 "10"
#define K6 "11"
#define K7 "12"
#define K8 "13"
#define K9 "14"
#define K10 "15"
// for enc/dec (contains value to work on)
#define XMM_SCRATCH "4"
// dec
#define DK "3"

// for inserting xmm into ymm without loss of ymm
#define YMM_SCRATCH "4"


/* XMM instructions */
#define XMM_LOAD(xmm_n, l, h) \
    __asm__ __volatile__ ( \
            "pinsrq $0, %0, %%xmm" xmm_n " \n\t" \
            "pinsrq $1, %1, %%xmm" xmm_n " \n\t" \
            : \
            : "r"((uint64_t)l), "r"((uint64_t)h) \
            : "xmm" xmm_n);
#define XMM_TO_VAR64(xmm_n, l, h) \
    __asm__ __volatile__ ( \
            "pinsrq $0, %0, %%xmm" xmm_n " \n\t" \
            "pinsrq $1, %1, %%xmm" xmm_n " \n\t" \
            : \
            : "r"((uint64_t)l), "r"((uint64_t)h) \
            : "xmm" xmm_n);
#define XMM_TO_VAR(xmm_n, v) \
    __asm__ __volatile__ ( \
            "movdqa %%xmm" xmm_n ", %0 \n\t" \
            : "=x"(v) \
            : \
            : "xmm" xmm_n);
#define XMM_FROM_VAR(xmm_n, v) \
    __asm__ __volatile__ ( \
            "movdqa %0, %%xmm" xmm_n " \n\t" \
            : \
            : "x"(v) \
            : "xmm" xmm_n);
#define XMM_XOR(xmm_v, xmm_k) \
    __asm__ __volatile__ ( \
            "xorps %%xmm" xmm_k ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_k);
#define XMM_TO_XMM(xmm_n, xmm_m) \
    __asm__ __volatile__ ( \
            "movdqa %%xmm" xmm_n ", %%xmm" xmm_m " \n\t" \
            : \
            : \
            : "xmm" xmm_n, "xmm" xmm_m);

/* YMM instructions */
#define YMM_UPPER_FROM_XMM(ymm_n, xmm_n) \
    __asm__ __volatile__ (\
            "vmovdqa %%ymm" ymm_n ", %%ymm" YMM_SCRATCH " \n\t" \
            "vinserti128 $1, %%xmm" xmm_n ", %%ymm" YMM_SCRATCH ", %%ymm" ymm_n " \n\t" \
            : \
            : \
            : "xmm" xmm_n, "ymm" ymm_n, "ymm" YMM_SCRATCH);
#define YMM_UPPER_TO_XMM(ymm_n, xmm_n) \
    __asm__ __volatile__ (\
            "vextracti128 $1, %%ymm" ymm_n ", %%xmm" xmm_n " \n\t" \
            : \
            : \
            : "xmm" xmm_n, "ymm" ymm_n);

#define YMM_TO_VAR(ymm_n, v) \
    __asm__ __volatile__ ( \
            "vmovdqa %%ymm" ymm_n ", %0 \n\t" \
            : "=x"(v) \
            : \
            : );

/* AES instruction */
#define AES_ENC(xmm_v, xmm_k) \
    __asm__ __volatile__ ( \
            "aesenc %%xmm" xmm_k ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_k);
#define AES_ENCLAST(xmm_v, xmm_k) \
    __asm__ __volatile__ ( \
            "aesenclast %%xmm" xmm_k ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_k);
#define AES_IMC(xmm_k, xmm_dk) \
    __asm__ __volatile__ ( \
            "aesimc %%xmm" xmm_k ", %%xmm" xmm_dk " \n\t" \
            : \
            : \
            : "xmm" xmm_k, "xmm" xmm_dk);
#define AES_DEC(xmm_v, xmm_dk) \
    __asm__ __volatile__ ( \
            "aesdec %%xmm" xmm_dk ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_dk);
#define AES_DECLAST(xmm_v, xmm_dk) \
    __asm__ __volatile__ ( \
            "aesdeclast %%xmm" xmm_dk ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_dk);
#define AES_KEYGEN(xmm_k, xmm_rk, rcon) \
    __asm__ __volatile__ ( \
            "aeskeygenassist $" #rcon ", %%xmm" xmm_k ", %%xmm" xmm_rk " \n\t" \
            : \
            : \
            : "xmm" xmm_k, "xmm" xmm_rk);

/* AES utils */
#define AES_ENCROUNDS(xmm_v) \
    XMM_XOR(xmm_v, K0); \
    AES_ENC(xmm_v, K1); \
    AES_ENC(xmm_v, K2); \
    AES_ENC(xmm_v, K3); \
    AES_ENC(xmm_v, K4); \
    AES_ENC(xmm_v, K5); \
    AES_ENC(xmm_v, K6); \
    AES_ENC(xmm_v, K7); \
    AES_ENC(xmm_v, K8); \
    AES_ENC(xmm_v, K9); \
    AES_ENCLAST(xmm_v, K10);

#define AES_DECROUNDS(xmm_v) \
    XMM_XOR(xmm_v, K10); \
    AES_DEC(xmm_v, K9); \
    AES_DEC(xmm_v, K8); \
    AES_DEC(xmm_v, K7); \
    AES_DEC(xmm_v, K6); \
    AES_DEC(xmm_v, K5); \
    AES_DEC(xmm_v, K4); \
    AES_DEC(xmm_v, K3); \
    AES_DEC(xmm_v, K2); \
    AES_DEC(xmm_v, K1); \
    AES_DECLAST(xmm_v, K0);

#define AES_KEYGEN_ALL(xmm_k) \
    XMM_TO_XMM(xmm_k, K0); \
    AES_KEYGEN(xmm_k, K1, 0x01); \
    AES_KEYGEN(xmm_k, K2, 0x02); \
    AES_KEYGEN(xmm_k, K3, 0x04); \
    AES_KEYGEN(xmm_k, K4, 0x08); \
    AES_KEYGEN(xmm_k, K5, 0x10); \
    AES_KEYGEN(xmm_k, K6, 0x20); \
    AES_KEYGEN(xmm_k, K7, 0x40); \
    AES_KEYGEN(xmm_k, K8, 0x80); \
    AES_KEYGEN(xmm_k, K9, 0x1B); \
    AES_KEYGEN(xmm_k, K10, 0x36); \

#define AES_IMC_ALL() \
    /* Not K0 */ \
    AES_IMC(K1, K1); \
    AES_IMC(K2, K2); \
    AES_IMC(K3, K3); \
    AES_IMC(K4, K4); \
    AES_IMC(K5, K5); \
    AES_IMC(K6, K6); \
    AES_IMC(K7, K7); \
    AES_IMC(K8, K8); \
    AES_IMC(K9, K9); \
    /* Not K10 */


#define AES_ENCROUNDS_FAKERK(xmm_v, xmm_rk) \
    XMM_XOR(xmm_v, xmm_rk); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_ENCLAST(xmm_v, xmm_rk);

#define AES_ENCROUNDS_KEYGEN(xmm_v, xmm_k, xmm_rk) \
    XMM_XOR(xmm_v, xmm_k); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x01); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x02); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x04); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x08); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x10); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x20); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x40); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x80); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x1B); \
    AES_ENC(xmm_v, xmm_rk); \
    AES_KEYGEN(xmm_k, xmm_rk, 0x36); \
    AES_ENCLAST(xmm_v, xmm_rk);

#endif
