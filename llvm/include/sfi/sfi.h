#ifndef _SFI_H
#define _SFI_H

#ifndef SFI_MASK
#ifdef __x86_64
#define SFI_MASK 0x7FFFFFFFFFFFFFFFL
#else
#define SFI_MASK 0xBFFFFFFF
#endif
#endif

#ifndef SFI_UB
#define SFI_UB SFI_MASK
#endif

typedef enum {
    SOFT,
    MPX,
    VMFUNC,
    MPK,
    CRYPT,
	DUMMY,
	REC,
    INSTRLIBCALL,
    __NUM_SFI_TYPES
} sfi_type_e;

#define SFI_TYPE_STRINGS \
    "soft", \
    "mpx", \
    "vmfunc", \
    "mpk", \
    "crypt", \
	"dummy",\
	"rec",\
    "instrlibcall",\
    NULL

#define sfi_type_from_str(S) ({ \
    const char *__x[] = { SFI_TYPE_STRINGS }; \
    sfi_type_e __e = (sfi_type_e) sfi_str_to_enum(S, __x); \
    __e; \
})

#define sfi_type_is_mem_all(X) ((X)==SOFT || (X)==MPX)

typedef enum {
	INS_ALL,
    MEM_ALL,
    MEM,
    CALL_RET,
    ICALL,
    LIBCALL,
    __NUM_SFI_POINTS
} sfi_points_e;

#define SFI_POINTS_STRINGS \
	"insall", \
    "memall", \
    "mem", \
    "call-ret", \
    "icall", \
    "libcall",\
    NULL

#define sfi_points_from_str(S) ({ \
    const char *__x[] = { SFI_POINTS_STRINGS }; \
    sfi_points_e __e = (sfi_points_e) sfi_str_to_enum(S, __x); \
    __e; \
})

static inline int sfi_str_to_enum(const char* str, const char **strs)
{
    int i=0;
    int val=-1;
    do {
        if (!strcmp(str, strs[i])) {
            val=i;
            break;
        }
    } while (strs[++i]);

    return val;
}

#endif /* _SFI_H */

