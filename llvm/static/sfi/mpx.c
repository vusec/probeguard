/*
 * Code to check for and enable Intel MPX. Stolen from libmpx, present in the
 * gcc source tree.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <cpuid.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#define REX_PREFIX      "0x48, "

#define bit_MPX	(1 << 14)
#define bit_BNDREGS     (1 << 3)
#define bit_BNDCSR      (1 << 4)

/* x86_64 directory size is 2GB */
#define NUM_L1_BITS   28

#define REG_IP_IDX    REG_RIP
#define REX_PREFIX    "0x48, "

#define XSAVE_OFFSET_IN_FPMEM    0

#define MPX_ENABLE_BIT_NO 0
#define BNDPRESERVE_BIT_NO 1

const size_t MPX_L1_SIZE = (1UL << NUM_L1_BITS) * sizeof (void *);

struct xsave_hdr_struct
{
  uint64_t xstate_bv;
  uint64_t reserved1[2];
  uint64_t reserved2[5];
} __attribute__ ((packed));

struct bndregs_struct
{
  uint64_t bndregs[8];
} __attribute__ ((packed));

struct bndcsr_struct {
	uint64_t cfg_reg_u;
	uint64_t status_reg;
} __attribute__((packed));

struct xsave_struct
{
  uint8_t fpu_sse[512];
  struct xsave_hdr_struct xsave_hdr;
  uint8_t ymm[256];
  uint8_t lwp[128];
  struct bndregs_struct bndregs;
  struct bndcsr_struct bndcsr;
} __attribute__ ((packed));

/* Following vars are initialized at process startup only
   and thus are considered to be thread safe.  */
static void *l1base = NULL;
static int bndpreserve = 1;
static int enable = 1;

static inline void
xrstor_state (struct xsave_struct *fx, uint64_t mask)
{
  uint32_t lmask = mask;
  uint32_t hmask = mask >> 32;

  __asm__ __volatile__ (".byte " REX_PREFIX "0x0f,0xae,0x2f\n\t"
		: : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
		:   "memory");
}

static void
enable_mpx (void)
{
  uint8_t __attribute__ ((__aligned__ (64))) buffer[4096];
  struct xsave_struct *xsave_buf = (struct xsave_struct *)buffer;

  memset (buffer, 0, sizeof (buffer));
  xrstor_state (xsave_buf, 0x18);

  fprintf (stderr, "Initalizing MPX...\n");
  fprintf (stderr, "  Enable bit: %d\n", enable);
  fprintf (stderr, "  BNDPRESERVE bit: %d\n", bndpreserve);

  /* Enable MPX.  */
  xsave_buf->xsave_hdr.xstate_bv = 0x10;
  xsave_buf->bndcsr.cfg_reg_u = (unsigned long)l1base;
  xsave_buf->bndcsr.cfg_reg_u |= enable << MPX_ENABLE_BIT_NO;
  xsave_buf->bndcsr.cfg_reg_u |= bndpreserve << BNDPRESERVE_BIT_NO;
  xsave_buf->bndcsr.status_reg = 0;

  xrstor_state (xsave_buf, 0x10);
}

static bool
check_mpx_support (void)
{
  unsigned int eax, ebx, ecx, edx;
  unsigned int max_level = __get_cpuid_max (0, NULL);

  if (max_level < 13)
    {
      fprintf (stderr, "No required CPUID level support.\n");
      return false;
    }

  __cpuid_count (0, 0, eax, ebx, ecx, edx);
  if (!(ecx & bit_XSAVE))
    {
      fprintf (stderr, "No XSAVE support.\n");
      return false;
    }

  if (!(ecx & bit_OSXSAVE))
    {
      fprintf (stderr, "No OSXSAVE support.\n");
      return false;
    }

  __cpuid_count (7, 0, eax, ebx, ecx, edx);
  if (!(ebx & bit_MPX))
    {
      fprintf (stderr, "No MPX support.\n");
      return false;
    }

  __cpuid_count (13, 0, eax, ebx, ecx, edx);
  if (!(eax & bit_BNDREGS))
    {
      fprintf (stderr, "No BNDREGS support.\n");
      return false;
    }

  if (!(eax & bit_BNDCSR))
    {
      fprintf (stderr, "No BNDCSR support.\n");
      return false;
    }

  return true;
}

static void
disable_mpx (void)
{
  uint8_t __attribute__ ((__aligned__ (64))) buffer[4096];
  struct xsave_struct *xsave_buf = (struct xsave_struct *)buffer;

  memset(buffer, 0, sizeof(buffer));
  xrstor_state(xsave_buf, 0x18);

  /* Disable MPX.  */
  xsave_buf->xsave_hdr.xstate_bv = 0x10;
  xsave_buf->bndcsr.cfg_reg_u = 0;
  xsave_buf->bndcsr.status_reg = 0;

  xrstor_state(xsave_buf, 0x10);
}

bool mpx_init_for_process(void)
{
  if (!check_mpx_support ())
    return false;

  l1base = mmap (NULL, MPX_L1_SIZE, PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (l1base == MAP_FAILED)
    {
      perror ("mmap");
      exit (EXIT_FAILURE);
    }

  enable_mpx ();

  if (prctl (43, 0, 0, 0, 0))
    {
      fprintf (stderr, "No MPX support\n");
      disable_mpx ();
      return false;
    }

  fprintf(stderr, "MPX enabled!\n");

  return true;
}

