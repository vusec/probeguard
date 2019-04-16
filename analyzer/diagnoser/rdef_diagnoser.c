#include "unistd.h"
#include "errno.h"
#include "rdef_diagnoser.h"

#define FILE_ACCESS_CHECK(F) \
  if (-1 == access(F, R_OK)) \
  {			     \
    rdef_print_error("Error accessing file: %s (%s)\n", F, strerror(errno)); \
    exit(errno);	     \
  }

// Cmd line argument values
static char *prog_filename = NULL;
static char *ptdump_filename = NULL;
static char *sideband_filename = NULL;
static rdef_prog_info_t *prog_files = NULL;
static unsigned num_prog_files = 0;
#define WINDOW_SIZE		1024 * 100
#define LLVMID_CACHE_SIZE	1024
static uint64_t insn_btrace_cache[WINDOW_SIZE];

static rdef_diagnoser_t diagnoser;

int rdef_diagnoser_init(char *pt_dump_filename, char *sideband_filename, rdef_prog_info_t prog_files[], unsigned num_prog_files, rdef_diagnoser_t *diagnoser)
{
  if (!diagnoser)
  {
    rdef_print_error("%s : Argument error.\n", __func__);
    return RDEF_E_FAIL;
  }

  // Initialize dwarf reader
  if (RDEF_E_OK != rdef_dwf_load(prog_filename))
  {
    return RDEF_E_FAIL;
  }
  diagnoser->dwarf_addr_map_loaded = 1;
  rdef_print_info("%s : successfully loaded dwarf binary and read its content.\n", __func__);

  // Initialize pt reader
  struct ptxed_options options;
  // TODO: Hard code them properly, or remove this completely
  options.track_image = 1;
  options.att_format = 1;

#if defined(FEATURE_ELF)
  options.elf_binary = 1;
#endif
  if (RDEF_E_OK != ptrdr_init(prog_files, num_prog_files, pt_dump_filename, sideband_filename, options, &diagnoser->pt_ctx.decoder, &diagnoser->pt_ctx.image))
  {
    return RDEF_E_FAIL;
  }
  return RDEF_E_OK;
}

/*
 * Reads the last <size> insn addreses into the <insn_btrace_window> starting from <from_offset> backwards.
 * eg. insn_btrace_window[0] is the next insn executed after insn_btrace_window[1] and
 * insn_btrace_window[0] has the insn addr found at the <from_offset> distance from the end of the trace. 
 * Return value is the number of insn addresses added into the btrace window.
*/
uint64_t rdef_get_last_insn_addrs(rdef_diagnoser_t *diagnoser, uint64_t *insn_btrace_window, uint64_t btrace_size, uint64_t from_offset)
{
  if (!diagnoser || (NULL == insn_btrace_window))
  {
    rdef_print_error("%s : Argument error\n", __func__);
    return 0;
  }
  if (0 == btrace_size)
	return 0;

  memset(insn_btrace_window, 0, btrace_size * sizeof(uint64_t));

  int is_eos = 0;
  int res = RDEF_E_OK;
  if (RDEF_E_FAIL == ptrdr_sync(diagnoser->pt_ctx.decoder, &is_eos, RDEF_TRACE_BACKWARDS, from_offset))
  {
    return RDEF_E_FAIL;
  }
  if (is_eos)
  {
     rdef_print_error("Reached end of stream.\n");
     return RDEF_E_FAIL;
  }
  uint64_t *p = insn_btrace_window + btrace_size - 1;
  uint64_t i;
  for (i = 0; i < btrace_size; i++)
  {
     if (RDEF_E_FAIL == ptrdr_next_insn_addr(diagnoser->pt_ctx.decoder, p, &is_eos))
     {
          rdef_print_warning("%s: failed getting next insn addr.\n", __func__);
          break;
     } 
     p--;
  }
  if (is_eos)
  {
     rdef_print_info("Reached end of stream.\n");
  }
  return i;
}

uint64_t rdef_get_last_llvm_id(rdef_diagnoser_t *diagnoser, uint64_t *last_addr)
{
  uint64_t window_size = 1024;
  uint64_t *btrace_window = (uint64_t *) calloc(window_size, sizeof(uint64_t));

  uint64_t llvmid = 0, curr_offset = 0, fetched = 0, count =0;
  while (llvmid == 0)
  {
    rdef_print_debug("count: %lu\n", count);
    fetched  = rdef_get_last_insn_addrs(diagnoser, btrace_window, window_size, curr_offset);
    if (fetched == 0)
        break;
    // note: btrace_window[0] has the last address and the window flows backwards.
    for (unsigned i = 0; i < fetched; i++)
    {
       if (btrace_window[i] == 0)
	  continue;
       llvmid = rdef_dwf_get_assigned_id(btrace_window[i]);
       if (0 != llvmid)
       {
	   if (last_addr)
		*last_addr = btrace_window[i];
	   break;
       }
    }
    curr_offset += fetched;
    count++;
  }
  rdef_print_info("Number of window traversals: %lu Btrace window size: %lu, llvmid:%lx\n", count, window_size, llvmid);
  return llvmid;
}

int rdef_get_unique_insn_addrs_from_dump(rdef_diagnoser_t *diagnoser, rdef_set_t **insn_addrs, uint64_t *num_insns)
{
  if (!diagnoser || !(diagnoser->dwarf_addr_map_loaded))
  {
    rdef_print_error("%s : Argument error\n", __func__);
    return RDEF_E_FAIL;
  }
  *insn_addrs = (rdef_set_t *) malloc (sizeof(rdef_set_t));
  memset(*insn_addrs, 0, sizeof(rdef_set_t));
  *num_insns = 0;
  int res;
  while(1)
  {
      int is_eos = 0;
      if (RDEF_E_FAIL == ptrdr_sync(diagnoser->pt_ctx.decoder, &is_eos, RDEF_TRACE_FORWARDS, 0))
      {
        return RDEF_E_FAIL;
      }
      rdef_print_info("ptrdr_sync done.\n");
      if (is_eos)
      {
        rdef_print_info("Reached end of stream.\n");
        res = RDEF_E_OK;
        break;
      }

      uint64_t next_addr = 0;
      do
      {
        if (RDEF_E_FAIL == ptrdr_next_insn_addr(diagnoser->pt_ctx.decoder, &next_addr, &is_eos))
        {
          rdef_print_warning("%s: failed getting next insn addr.\n", __func__);
          break;
        }
        rdef_set_element_t *lookup;
        HASH_FIND_PTR((*insn_addrs)->index, &next_addr, lookup);
        if (NULL == lookup)
        {
          rdef_set_element_t *new_elem = &((*insn_addrs)->set[(*insn_addrs)->next_free]);
          new_elem->value = next_addr;
          (*num_insns)++;
          HASH_ADD_PTR((*insn_addrs)->index, value, new_elem);
          rdef_print_info("Added address: %lu to the set.\n", next_addr);
        }
      }while(next_addr != 0);

      if (is_eos)
      {
        rdef_print_info("Reached end of stream.\n");
        res = RDEF_E_OK;
        break;
      }
   }

  if (RDEF_E_OK == res)
  {
    ptrdr_close(diagnoser->pt_ctx.decoder, diagnoser->pt_ctx.image);
    return RDEF_E_OK;
  }
  rdef_print_error("%s : Something went wrong.\n", __func__);
  return RDEF_E_FAIL;
}

void print_addrs(rdef_set_t *insn_addr_set)
{
  rdef_set_element_t *r;

  printf("Binary instruction addresses found in pt dump:\n");
  uint64_t i = 0;
  for (r=insn_addr_set->index; r != NULL; r=r->hh.next, i++)
  {
    printf("%lu) %lx \n", i, r->value);
  }
  return;
}

void print_addr_map(rdef_set_t *insn_addr_set)
{
  rdef_set_element_t *r;

  printf("Binary instruction addresses found in pt dump:\n");
  for (r=insn_addr_set->index; r != NULL; r=r->hh.next)
  {
    uint64_t id = rdef_dwf_get_assigned_id(r->value);
    printf("addr) %lx ==> id) %lx\n", r->value, id);
  }
  return;
}

static int extract_base(char *arg, uint64_t *base)
{
        char *sep, *rest;

        sep = strrchr(arg, ':');
        if (sep) {
                uint64_t num;

                if (!sep[1])
                        return 0;

                errno = 0;
                num = strtoull(sep+1, &rest, 0);
                if (errno || *rest)
                        return 0;

                *base = num;
                *sep = 0;
                return 1;
        }

        return 0;
}

static int parse_args(int argc, char **argv)
{
  int min_args = 2;
  int opt_arg_begin = min_args + 1;

  if (argc <= min_args)
  {
    printf("Usage: %s <executable path> <pt dump path> [ ELF files information ]\n", argv[0]);
    printf("\nELF files information:\n");
    printf("\t%-30s \t%s\n", "-s <sideband filename>", "file generated by sptsideband.py");
    printf("\t%-30s \t%s\n", "--elf <filename>:<base>", "specify one by one, all the other loaded elf binaries and their load addresses");
    printf("\n");
    exit(1);
  }
  
  // positional args
  if (-1 == access(argv[1], R_OK))
  {
    rdef_print_error("Error accessing program file: %s (%s)\n", argv[1], strerror(errno));
    exit(errno);
  }
  prog_filename = argv[1];

  if (-1 == access(argv[2], R_OK))
  {
    rdef_print_error("Error accessing PT dump file: %s (%s)\n", argv[2], strerror(errno));
    exit(errno);
  }
  ptdump_filename = argv[2];

  int num_elves = (argc - opt_arg_begin)/2;
  int *elf_args = calloc(num_elves, sizeof(int)); // it is ok if we allocate more; less is not acceptable.
  int elf_pos = -1;

  for (unsigned argi = opt_arg_begin; argi < argc; argi++)
  {
    char *curr = argv[argi];
    //rdef_print_info("curr arg: %s\n", curr);

    if (!sideband_filename && (!strcmp(argv[argi], "-s")))
    {
	sideband_filename = argv[++argi];
  	if (-1 == access(sideband_filename, R_OK))
  	{
	    rdef_print_error("Error accessing sideband file: %s (%s)\n", sideband_filename, strerror(errno));
	    exit(errno);
 	}
	continue;
    }
    if (!strcmp(argv[argi], "--elf"))
    {
	argi++;
	elf_pos++;
	*(elf_args+elf_pos) = argi;
    }
  }

  rdef_print_info("elf_pos: %d\n", elf_pos);
  num_prog_files = elf_pos+1;
  prog_files = (rdef_prog_info_t *) calloc((elf_pos+1) , sizeof(rdef_prog_info_t));
  // default values
  prog_files[0].filename = prog_filename;
  prog_files[0].base = 0;
  
  //rdef_print_info("Constructing rdef_prog_info_t values...\n");

  for (int i = 0; i <= elf_pos; i++)
  {

    prog_files[i].filename = argv[*(elf_args+i)];
    int ret = extract_base(argv[*(elf_args+i)], &(prog_files[i].base));
    if (!ret)
    {
	prog_files[i].base = 0;
    }
    FILE_ACCESS_CHECK(prog_files[i].filename);
  }

  free(elf_args); 

  return 0;
}

int main(int argc, char **argv)
{
  rdef_diagnoser_t diagnoser;
  rdef_set_t *insn_addr_set;
  uint64_t  num_insns;

  parse_args(argc, argv);
  rdef_print_debug("Arg parsing done.\n");

  int result;
  result = rdef_diagnoser_init(ptdump_filename, sideband_filename, prog_files, num_prog_files, &diagnoser);
  if (RDEF_E_FAIL == result)
  {
    rdef_print_error("Failed initializing diagnoser.\n");
    return 1;
  }
  rdef_print_debug("Diagnoser initialized.\n");

  uint64_t last_addr = 0;
  uint64_t last_llvmid = rdef_get_last_llvm_id(&diagnoser, &last_addr);
  rdef_print_info("Last LLVM ID found: %lu for address: 0x%lx\n", last_llvmid, last_addr);
  return 0;

  uint64_t num_contents = 0;
  uint64_t *btrace_window = (uint64_t *) calloc(WINDOW_SIZE, sizeof(uint64_t));
  num_contents = rdef_get_last_insn_addrs(&diagnoser, btrace_window, WINDOW_SIZE, 0); 
  rdef_print_info("Fetched %lu number of back traced instruction addresses.\n", num_contents);
  for(uint64_t i=0; i < num_contents; i++)
  {
    printf("instr addr: 0x%lx dwarf-ins-id: %lu \n", btrace_window[i], rdef_dwf_get_assigned_id(btrace_window[i]));
  }

  free(btrace_window);
#if 0
  result = rdef_get_unique_insn_addrs_from_dump(&diagnoser, &insn_addr_set, &num_insns);
  if (RDEF_E_FAIL == result)
  {
    return 1;
  }
  print_addrs(insn_addr_set);
  print_addr_map(insn_addr_set);
#endif

  return 0;
}
