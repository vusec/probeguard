#include "rdef_dwarf.h"

static addr_llvm_id_map_t addr_llvm_id_map;
static uint8_t g_map_loaded = 0;

static Dwarf_Die get_cu_die(Dwarf_Debug dbg, const char *die_name_filter, int *pres)
{
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Unsigned next_cu_header = 0;
    Dwarf_Error error;
    int cu_number = 0;
    int res = RDEF_E_FAIL;
    int found = 0;	// Not found

    Dwarf_Die cu_die = 0;
    for ( ;; ++cu_number) {
        Dwarf_Die no_die = 0;
        res = DW_DLV_ERROR;
        res = dwarf_next_cu_header(dbg, &cu_header_length,
            &version_stamp, &abbrev_offset, &address_size,
            &next_cu_header, &error);
        if (res == DW_DLV_ERROR) {
            rdef_print_error("Error in dwarf_next_cu_header\n");
            exit(RDEF_E_FAIL);
        }
        if (res == DW_DLV_NO_ENTRY) {
            /* Done. */
            rdef_print_info("DW_DLV_NO_ENTRY\n") ;
            if (!found)
		exit(RDEF_E_FAIL);
	    break; // success
        }

        /* The CU may have several siblings - multiple cu_die entries.
	 * We iterate on them to find the one specified by the filter.
         */
        res = dwarf_siblingof(dbg, no_die, &cu_die, &error);
        if (res == DW_DLV_ERROR) {
            rdef_print_error("Error in dwarf_siblingof on CU die \n");
            exit(RDEF_E_FAIL);
        }
        if (res == DW_DLV_NO_ENTRY) {
            /* Impossible case. */
            rdef_print_error("no entry! in dwarf_siblingof on CU die \n");
            exit(RDEF_E_FAIL);
        }
        rdef_print_info("cu_number = %d\n", cu_number);

        Dwarf_Half tagval;
        res = dwarf_tag(cu_die, &tagval, &error);
        if (res == DW_DLV_OK && tagval == DW_TAG_compile_unit)
        {
          rdef_print_info("cu_die has DW_TAG_compile_unit tag.\n");
        }
	char *die_name;
	res = dwarf_diename(cu_die, &die_name, &error);
	if (res == DW_DLV_OK) {
	    rdef_print_info("cu_die has name: %s\n", die_name);
	    if (NULL != strstr(die_name, die_name_filter)) {
		found = 1;
		break; // success
	    }
	} else if (res == DW_DLV_NO_ENTRY) {
	    rdef_print_info("cu_die has no name!.\n");
	}
    }

  *pres = res;
  return cu_die;
}

int rdef_dwf_load(const char *prog)
{
  int retval = RDEF_E_FAIL;
  int prog_fd;

  prog_fd = open(prog, O_RDONLY);
  if (prog_fd < 0)
  {
    rdef_print_error("Failure attempting to open %s\n", prog);
    return RDEF_E_FAIL;
  }

  memset(&addr_llvm_id_map, 0, sizeof(addr_llvm_id_map));
  addr_llvm_id_map.next_free = 0; // redundant

  /* initialize dwarf structures */
  Dwarf_Debug dbg;
  Dwarf_Error error;
  Dwarf_Handler errhand = 0;
  Dwarf_Ptr errarg = 0;
  int res = 0;
  res = dwarf_init(prog_fd, DW_DLC_READ, errhand, errarg, &dbg, &error);
  if (res != DW_DLV_OK) {
      rdef_print_error("dwarf_init() failed.\n");
      return RDEF_E_FAIL;
  }

  char prog_basename[RDEF_MAX_STR_SIZE];
  assert(strlen(prog_basename) < RDEF_MAX_STR_SIZE);
  RDEF_BASENAME(prog_basename, prog, strlen(prog));
  if (0 == strlen(prog_basename)) {
	rdef_print_error("Failed fetching basename of the specified program: %s\n", prog);
	return RDEF_E_FAIL;
  }
  Dwarf_Die cu_die = get_cu_die(dbg, prog_basename, &res);
  if (!cu_die) {
    rdef_print_error("Failure getting cu_die\n");
      if(res == DW_DLV_ERROR)
          return RDEF_E_FAIL;
      else
          goto finish;
  }

  Dwarf_Signed cnt, i;
  Dwarf_Line *linebuf;
  int sres;
  if ((sres = dwarf_srclines(cu_die, &linebuf,&cnt, &error)) != DW_DLV_OK)
  {
    rdef_print_error("Failed fetching srclines.\n");
    return RDEF_E_FAIL;
  }

  rdef_print_info("Num srclines fetched: %lld\n", cnt);

  for(i=0; i < cnt; i++)
  {
    Dwarf_Line currLine = linebuf[i];
    Dwarf_Addr lineAddr;
    Dwarf_Signed colNum;
    if (DW_DLV_OK != dwarf_lineaddr(currLine, &lineAddr, &error))
    {
      rdef_print_error("Could not fetch address.\n");
      return RDEF_E_FAIL;
    }
    if (DW_DLV_OK != dwarf_lineoff(currLine, &colNum, &error))
    {
      rdef_print_error("Could not fetch line offset (col num).\n");
      return RDEF_E_FAIL;
    }
    map_element_t *elem = NULL;
    // HASH_FIND(hh, addr_llvm_id_map.map, &lineAddr, sizeof(uint64_t), elem);
    HASH_FIND_PTR(addr_llvm_id_map.index, &lineAddr, elem);
    if (NULL == elem) // elem not found
    {
      if (addr_llvm_id_map.next_free >= RDEF_MAX_HMAP_SIZE)
      {
        rdef_print_error("Hashtable already filled. No more space.\n");
        g_map_loaded = 0;
        return RDEF_E_FAIL;
      }
      map_element_t *new_node = &(addr_llvm_id_map.map[addr_llvm_id_map.next_free++]);
      new_node->addr = (uint64_t) lineAddr;
      new_node->llvm_id = (uint64_t) colNum;
      HASH_ADD_PTR(addr_llvm_id_map.index, addr, new_node);
      rdef_print_debug("dwarf mapping -- addr [%lx] : llvm-id [%lu] \n", new_node->addr, new_node->llvm_id);
    }
  }

  retval = RDEF_E_OK;
  g_map_loaded = 1;

  // Clean up Dwarf related structures
  dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);

  finish:
  res = dwarf_finish(dbg, &error);
  if (res != DW_DLV_OK)
  {
      rdef_print_error("dwarf_finish() failed.\n");
      return RDEF_E_FAIL;
  }
  return retval;
}

uint64_t rdef_dwf_get_assigned_id(uint64_t addr)
{
  if (0 == g_map_loaded)
  {
    rdef_print_info("addr -> llvm_id map not loaded yet.\n");
    return 0;
  }
  map_element_t *lookup = NULL;
  HASH_FIND_PTR(addr_llvm_id_map.index, &addr, lookup);
  if (NULL == lookup)
  {
    return 0; // invalid llvm id
  }
  return lookup->llvm_id;
}
