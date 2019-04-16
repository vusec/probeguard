#include <pass.h>

#include <BinaryFunction.h>
#include <Dereference.h>
#include <Immediate.h>
#include <InstructionAST.h>

#include <elfio/elfio.hpp>

#include <unconditionalize/ucpatch.h>
#include "rdef_dwarf.h"

#include <BPatch.h>
#include <BPatch_statement.h>

PASS_ONCE();

#define unconditionalizePassLog(M) (errs() << "UnconditionalizePass: " << M << "\n")
#define unconditionalizePassDbg(M) DEBUG(dbgs() << "UnconditionalizePass [DEBUG]: " << M << "\n")

#define NO_BBINDEX 1

#define RDEF_DWARF 1
#ifdef RDEF_DWARF
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
    int found = 0;      // Not found

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
#endif

static cl::opt<std::string>
clOptGVarName("unconditionalize-varname",
    cl::desc("Name of the global variable name that branch instructions are based upon."),
    cl::init("edfi_inject_bb"));

static cl::opt<bool>
clOptVarsPerFunction("unconditionalize-vars-per-function",
    cl::desc("If true, the global variable is assumed to be an array, with respective indices used by every function in the binary"),
    cl::init(false));

static cl::opt<bool>
clOptVarsValue("unconditionalize-vars-set-to",
    cl::desc("If true, the global variables are assumed to be set to TRUE; otherwise FALSE [ default: false ]"),
    cl::init(false));

static cl::opt<std::string>
clOptSkipSection("unconditionalize-skip-section",
    cl::desc("Specify name of the section where unconditionalizing functions must be skipped."),
    cl::init(""));

namespace {

  typedef uint32_t targetptr_t; /* this should not be hardcoded */

  enum patchmode {
    mode_unknown,
    mode_nop,
    mode_unconditional,
  };

  struct patchloc {
    long bb_index;
    enum patchmode mode;
    unsigned long cmp_addr;
    size_t cmp_size;
    unsigned long jmp_addr;
    size_t jmp_size;
    bool found;
  };

  struct patchbyte {
    ELFIO::Elf64_Off offset;
    long bb_index;		// in per-function mode, we reuse this field for func_id
    unsigned char value_orig;
    unsigned char value_new;
  };

  struct funcboundary {
    void *func_start;
    void *func_end;
  };

  struct funcpatchloc {
    long func_id;
    enum patchmode mode;
    unsigned long cmp_addr;
    size_t cmp_size;
    unsigned long jmp_addr;
    size_t jmp_size;
    void *true_block_start, *false_block_start;
    size_t true_block_size, false_block_size;
    bool found;
  };

  bool compare_patchbyte_offset(const struct patchbyte &first, const struct patchbyte &second) {
    return first.offset < second.offset;
  }

  int compare_patchbyte_bbindex_int(const struct patchbyte &first, const struct patchbyte &second) {
    if (first.bb_index < second.bb_index) return -1;
    if (first.bb_index > second.bb_index) return 1;
    if (first.offset < second.offset) return -1;
    if (first.offset > second.offset) return 1;
    return 0;
  }

  bool compare_patchbyte_bbindex(const struct patchbyte &first, const struct patchbyte &second) {
    return compare_patchbyte_bbindex_int(first, second) < 0;
  }

  bool compare_patchloc_bbindex(const struct patchloc &first, const struct patchloc &second) {
    return first.bb_index < second.bb_index;
  }

  bool compare_funcpatchloc_funcid(const struct funcpatchloc &first, const struct funcpatchloc &second) {
    return first.func_id < second.func_id;
  }

  class UnconditionalizePass : public ModulePass {

  private:

    std::vector<unsigned long> func_addrs;
    std::map<unsigned long, struct funcboundary> func_map;

    static std::string instructionCategoryName(Dyninst::InstructionAPI::InsnCategory cat) {
      switch (cat) {
      case Dyninst::InstructionAPI::c_CallInsn: return "c_CallInsn";
      case Dyninst::InstructionAPI::c_ReturnInsn: return "c_ReturnInsn";
      case Dyninst::InstructionAPI::c_BranchInsn: return "c_BranchInsn";
      case Dyninst::InstructionAPI::c_CompareInsn: return "c_CompareInsn";
      case Dyninst::InstructionAPI::c_NoCategory: return "c_NoCategory";
      default: return "???";
      }
    }

    bool evalConstantExpressionBinary(Dyninst::InstructionAPI::BinaryFunction &expression, unsigned long ip, unsigned long &value) {
      std::vector<Dyninst::InstructionAPI::Expression::Ptr> children;
      unsigned long value1, value2;

      assert((expression.isAdd() ? 1 : 0) + (expression.isMultiply() ? 1 : 0) == 1);

      expression.getChildren(children);
      assert(children.size() == 2);

      if (!evalConstantExpression(*children[0], ip, value1) ||
          !evalConstantExpression(*children[1], ip, value2)) {
	  value = 0;
	  return false;
      }

      if (expression.isAdd()) {
	  value = value1 + value2;
      } else {
	  value = value1 * value2;
      }
      return true;
    }

    bool evalConstantExpressionImmediate(Dyninst::InstructionAPI::Immediate &expression, unsigned long &value) {
      value = expression.eval().convert<unsigned long>();
      return true;
    }

    bool evalConstantExpressionRegister(Dyninst::InstructionAPI::RegisterAST &expression, unsigned long ip, unsigned long &value) {
      if (expression.getID() == Dyninst::x86::eip || expression.getID() == Dyninst::x86_64::rip) {
          value = ip;
          return true;
      }

      value = 0;
      return false;
    }

    bool evalConstantExpression(Dyninst::InstructionAPI::InstructionAST &expression, unsigned long ip, unsigned long &value) {
      Dyninst::InstructionAPI::BinaryFunction *binary;
      Dyninst::InstructionAPI::Immediate *immediate;
      Dyninst::InstructionAPI::RegisterAST *reg;

//      unconditionalizePassDbg("evalConstExpr: ip: " << std::hex << ip << " value: " << value << std::dec);
      binary = dynamic_cast<Dyninst::InstructionAPI::BinaryFunction *>(&expression);
      if (binary) return evalConstantExpressionBinary(*binary, ip, value);

      immediate = dynamic_cast<Dyninst::InstructionAPI::Immediate *>(&expression);
      if (immediate) return evalConstantExpressionImmediate(*immediate, value);

      reg = dynamic_cast<Dyninst::InstructionAPI::RegisterAST *>(&expression);
      if (reg) return evalConstantExpressionRegister(*reg, ip, value);

      value = 0;
      return false;
    }

    bool evalConstantExpressionOrPtr(Dyninst::InstructionAPI::InstructionAST &expression, unsigned long ip, bool &is_pointer, unsigned long &value) {
      std::vector<Dyninst::InstructionAPI::Expression::Ptr> children;
      Dyninst::InstructionAPI::Dereference *dereference;

      dereference = dynamic_cast<Dyninst::InstructionAPI::Dereference *>(&expression);
      if (dereference) {
          is_pointer = true;
	  dereference->getChildren(children);
	  assert(children.size() == 1);
          return evalConstantExpression(*children[0], ip, value);
      } else {
          is_pointer = false;
          return evalConstantExpression(expression, ip, value);
      }
    }

    bool instructionIsFuncController(Dyninst::InstructionAPI::Instruction::Ptr instruction, unsigned long ip, BPatch_variableExpr *var_inject_bb, struct funcpatchloc &fpatchloc, unsigned long func_id=0) {
      bool immediate_found = false;
      bool is_pointer;
      std::vector<Dyninst::InstructionAPI::Operand>::iterator it;
      std::vector<Dyninst::InstructionAPI::Operand> operands;
      bool other_found = false;
      unsigned long value;
      bool var_found = false;

      instruction->getOperands(operands);
      for (it = operands.begin(); it != operands.end(); ++it) {
          if (!evalConstantExpressionOrPtr(*it->getValue(), ip + instruction->size(), is_pointer, value)) {
              other_found = true;
          } else if (!is_pointer) {
              if (immediate_found) {
                  unconditionalizePassLog("Warning: Instruction with multiple immediate operands found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
                  continue;
              }
              if ((targetptr_t) value == (targetptr_t) (ptrdiff_t) var_inject_bb->getBaseAddr()) {
                  unconditionalizePassLog("Warning: Instruction that does not dereference pointer to edfi_inject_bb found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
                  continue;
              }
              immediate_found = true;
          } else if ((targetptr_t) value == (targetptr_t) (ptrdiff_t) var_inject_bb->getBaseAddr() + (targetptr_t)(sizeof(unsigned) * func_id)) {
	      if (var_found) {
                  unconditionalizePassLog("Warning: Instruction with multiple references to edfi_inject_bb found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
                  continue;
              }
              if (it->isWritten()) {
                  unconditionalizePassLog("Warning: Instruction writing edfi_inject_bb found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
                  continue;
              }
              var_found = true;
          } else if (instructionReadsRegister(instruction, Dyninst::x86_64::rip)) {
                 if (it->readsMemory()) {
                      // This is potentially the branch instruction that we care about.
                      std::set<Dyninst::InstructionAPI::Expression::Ptr> memAccessors;
                      it->addEffectiveReadAddresses(memAccessors);
                      for (std::set<Dyninst::InstructionAPI::Expression::Ptr>::iterator IM = memAccessors.begin(), EM = memAccessors.end(); IM != EM; IM++) {
                          Dyninst::InstructionAPI::Expression::Ptr expPtr = *IM;
                          if (evalConstantExpression(*expPtr, ip, value)) {
                              unconditionalizePassDbg("memAccessor value: " << std::hex << value << " baseaddr of array: " << var_inject_bb->getBaseAddr()
                                                  << " instr size: " << instruction->size() << " offset: " << func_id
                                                  << " expected value: " << (targetptr_t) (ptrdiff_t) var_inject_bb->getBaseAddr() + (targetptr_t) (sizeof(unsigned) * func_id) - instruction->size() << std::dec);
                              if (value == (targetptr_t) (ptrdiff_t) var_inject_bb->getBaseAddr() + (targetptr_t)(sizeof(unsigned) * func_id) - instruction->size()) {
                                        unconditionalizePassDbg("per-function behaviour controlling branch inst. and its operand found.");
                                        var_found = true;
                              }
                         }
                      }
                 }
          } else {
	        other_found = true;
          }
	} // for operands iteration ends
      if (!var_found) return false;
      if (!immediate_found) {
          unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb without immediate operand found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
          return false;
      }
      if (other_found) {
          unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb with unexpected additional operand found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
          return false;
      }
      if (instruction->getCategory() != Dyninst::InstructionAPI::c_CompareInsn) {
          unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb with unexpected category found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
          return false;
      }
      if (instruction->getOperation().getID() != e_cmp) {
          unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb with unexpected operation found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
          return false;
      }
      // now populate the two funcpatchblocks
      fpatchloc.func_id = func_id;
      fpatchloc.cmp_addr = ip;
      fpatchloc.cmp_size = instruction->size();
      return true;
    }


    bool instructionIsBasicBlockTest(Dyninst::InstructionAPI::Instruction::Ptr instruction, unsigned long ip, BPatch_variableExpr *var_inject_bb, long &bb_index) {
      unsigned long immediate = -1;
      bool immediate_found = false;
      bool is_pointer;
      std::vector<Dyninst::InstructionAPI::Operand>::iterator it;
      std::vector<Dyninst::InstructionAPI::Operand> operands;
      bool other_found = false;
      unsigned long value;
      bool var_found = false;

      instruction->getOperands(operands);
      for (it = operands.begin(); it != operands.end(); ++it) {
          if (!evalConstantExpressionOrPtr(*it->getValue(), ip + instruction->size(), is_pointer, value)) {
	      other_found = true;
	  } else if (!is_pointer) {
	      if (immediate_found) {
	          unconditionalizePassLog("Warning: Instruction with multiple immediate operands found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
		  continue;
	      }
	      if ((targetptr_t) value == (targetptr_t) (ptrdiff_t) var_inject_bb->getBaseAddr()) {
	          unconditionalizePassLog("Warning: Instruction that does not dereference pointer to edfi_inject_bb found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
		  continue;
	      }
	      immediate = value;
	      immediate_found = true;
	  } else if ((targetptr_t) value == (targetptr_t) (ptrdiff_t) var_inject_bb->getBaseAddr()) {
	      if (var_found) {
	          unconditionalizePassLog("Warning: Instruction with multiple references to edfi_inject_bb found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
		  continue;
	      }
	      if (it->isWritten()) {
	          unconditionalizePassLog("Warning: Instruction writing edfi_inject_bb found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
		  continue;
	      }
	      var_found = true;
	 } else {
	      other_found = true;
	 } 
      } // for iterating on operands ends.
      if (!var_found) return false;
      if (!immediate_found) {
	  unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb without immediate operand found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
	  return false;
      }
      if (other_found) {
	  unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb with unexpected additional operand found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
	  return false;
      }
      if (instruction->getCategory() != Dyninst::InstructionAPI::c_CompareInsn) {
	  unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb with unexpected category found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
	  return false;
      }
      if (instruction->getOperation().getID() != e_cmp) {
	  unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb with unexpected operation found at 0x" << std::hex << ip << std::dec << ": " << instruction->format());
	  return false;
      }
      bb_index = immediate;
      return true;
    }

    static bool instructionWritesRegister(
      Dyninst::InstructionAPI::Instruction::Ptr instruction,
      Dyninst::MachRegister reg) {
      std::set<Dyninst::InstructionAPI::RegisterAST::Ptr>::iterator it;
      std::set<Dyninst::InstructionAPI::RegisterAST::Ptr> regsWritten;

      instruction->getWriteSet(regsWritten);
      for (it = regsWritten.begin(); it != regsWritten.end(); ++it) {
          if ((*it)->getID() == reg) return true;
      }
      return false;
    }

    static bool instructionReadsRegister(
      Dyninst::InstructionAPI::Instruction::Ptr instruction,
      Dyninst::MachRegister reg) {
      std::set<Dyninst::InstructionAPI::RegisterAST::Ptr>::iterator it;
      std::set<Dyninst::InstructionAPI::RegisterAST::Ptr> regsRead;

      instruction->getReadSet(regsRead);
      for (it = regsRead.begin(); it != regsRead.end(); ++it) {
          if ((*it)->getID() == reg) return true;
      }
      return false;
   }

    void remove_duplicate_patchlocs(std::list<struct patchloc> &patchlocs) {
      std::list<struct patchloc>::iterator it, itnext;

      patchlocs.sort(compare_patchloc_bbindex);
      it = patchlocs.begin();
      while (it != patchlocs.end()) {
	  itnext = it;
	  itnext++;
	  if (itnext != patchlocs.end() && it->bb_index == itnext->bb_index) {
              if (it->cmp_addr != itnext->cmp_addr ||
	          it->cmp_size != itnext->cmp_size ||
	          it->jmp_addr != itnext->jmp_addr ||
	          it->jmp_size != itnext->jmp_size) {
	          unconditionalizePassLog("Warning: basic block " << it->bb_index <<
		      " found twice, at addresses 0x" << std::hex << it->cmp_addr <<
		      " and 0x" << itnext->cmp_addr << std::dec);
	      }
              unconditionalizePassDbg("Removing duplicate basic block " << it->bb_index <<
	          " found multiple times at 0x" << std::hex << it->cmp_addr << std::dec);
	      patchlocs.erase(it);
	  }
          it = itnext;
      }
    }

   void remove_duplicate_patchlocs(std::list<struct funcpatchloc> &fpatchlocs) {
      std::list<struct funcpatchloc>::iterator it, itnext;

      fpatchlocs.sort(compare_funcpatchloc_funcid);
      it = fpatchlocs.begin();
      while (it != fpatchlocs.end()) {
          itnext = it;
          itnext++;
          if (itnext != fpatchlocs.end() && it->func_id == itnext->func_id) {
              if (it->cmp_addr != itnext->cmp_addr ||
                  it->cmp_size != itnext->cmp_size ||
                  it->jmp_addr != itnext->jmp_addr ||
                  it->jmp_size != itnext->jmp_size) {
                  unconditionalizePassLog("Warning: function " << it->func_id <<
                      " found twice, at addresses 0x" << std::hex << it->cmp_addr <<
                      " and 0x" << itnext->cmp_addr << std::dec);
              }
              unconditionalizePassDbg("Removing duplicate func " << it->func_id <<
                  " found multiple times at 0x" << std::hex << it->cmp_addr << std::dec);
              fpatchlocs.erase(it);
          }
          it = itnext;
      }
    }

    const void *get_elf_data(ELFIO::elfio &reader, unsigned long addrfrom, unsigned long addrto) {
      int secidx;
      ELFIO::section *section;

      assert(addrfrom <= addrto);
      for (secidx = 0; secidx < reader.sections.size(); secidx++) {
	  section = reader.sections[secidx];
          if (addrfrom >= section->get_address() &&
	      addrto < section->get_address() + section->get_size()) {
	      return section->get_data() + addrfrom - section->get_address();
	  }
      }
      unconditionalizePassLog("Warning: Address range 0x" << std::hex << addrfrom << " to 0x" << addrto << std::dec << " not found in ELF file sections");
      return NULL;
    }

    bool get_elf_instructions(ELFIO::elfio &reader, BPatch_basicBlock *bb,
      unsigned long addrfrom, unsigned long addrto,
      std::vector<Dyninst::InstructionAPI::Instruction::Ptr> &instructions) {
      const void *data = get_elf_data(reader, addrfrom, addrto);
      if (!data) return false;

      bb->getInstructions(instructions, data);
      return true;
    }

    void dumpInstructions(std::vector<Dyninst::InstructionAPI::Instruction::Ptr> &instructions, unsigned long addr) {
      Dyninst::InstructionAPI::Instruction::Ptr instruction;
      std::vector<Dyninst::InstructionAPI::Instruction::Ptr>::iterator it;

      for (it = instructions.begin(); it != instructions.end(); ++it) {
           instruction = *it;
           unconditionalizePassLog("Dump: 0x" << std::hex << addr << std::dec << ": " << instruction->format());
	   addr += instruction->size();
      }
    }

    void runOnBasicBlock(ELFIO::elfio &reader, BPatch_basicBlock *bb, BPatch_variableExpr *var_inject_bb, std::list<struct patchloc> &patchlocs, unsigned long func_id=0) {
      unsigned long addr = bb->getStartAddress();
      unsigned long addrStart = addr;
      long bb_index = -1;
      Dyninst::InstructionAPI::Instruction::Ptr instruction;
      std::vector<Dyninst::InstructionAPI::Instruction::Ptr> instructions;
      std::vector<Dyninst::InstructionAPI::Instruction::Ptr>::iterator it;
      struct patchloc patchloc;
      unsigned long readAddr;

      get_elf_instructions(reader, bb, addr, bb->getEndAddress(), instructions);
      memset(&patchloc, 0, sizeof(patchloc));
      for (it = instructions.begin(); it != instructions.end(); ++it) {
           instruction = *it;
	   addr += instruction->size();
	   if (!instruction->isValid()) {
               unconditionalizePassLog("Warning: Invalid instruction at 0x" << std::hex << (addr - instruction->size()) << std::dec);
	       dumpInstructions(instructions, addrStart);
               return;
	   }
	   if (!instruction->isLegalInsn()) {
               unconditionalizePassLog("Warning: Illegal instruction at 0x" << std::hex << (addr - instruction->size()) << std::dec);
	       dumpInstructions(instructions, addrStart);
               return;
	   }

	   if (instructionIsBasicBlockTest(instruction, addr - instruction->size(), var_inject_bb, bb_index)) {
	       patchloc.cmp_addr = addr - instruction->size();
	       patchloc.cmp_size = instruction->size();
	       if (clOptVarsPerFunction)   bb_index = func_id;
	       continue;
	   }
	   if (bb_index < 0) continue;
           if (instruction->getCategory() != Dyninst::InstructionAPI::c_BranchInsn) {
	       if (instructionWritesRegister(instruction, Dyninst::x86::zf)) {
	           unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb followed by ZF-modifying instruction at 0x" << std::hex << (addr - instruction->size()) << std::dec << ": " << instruction->format());
	       }
	       continue;
           }
           switch (instruction->getOperation().getID()) {
           case e_jnz:
               patchloc.mode = mode_unconditional;
               break;
           case e_jz:
               patchloc.mode = mode_nop;
               break;
           default:
	       unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb followed by unexpected type of branch instruction at 0x" << std::hex << (addr - instruction->size()) << std::dec << ": " << instruction->format());
	       dumpInstructions(instructions, addrStart);
	       continue;
           }
	   if (it + 1 != instructions.end()) {
               unconditionalizePassLog("Warning: Branch before end of basic block " << bb_index << " at 0x" << std::hex << (addr - instruction->size()) << std::dec << ": " << instruction->format() << "; next: " << (*(it + 1))->format());
	       dumpInstructions(instructions, addrStart);
	       return;
	   }
	   patchloc.bb_index = bb_index;
	   patchloc.jmp_addr = addr - instruction->size();
	   patchloc.jmp_size = instruction->size();
	   unconditionalizePassDbg("Adding patchloc for func_id: " << std::hex << func_id << " (bb_index = " << bb_index << ")" << "cmp_addr: " << patchloc.cmp_addr << std::dec);
	   patchlocs.push_back(patchloc);
           unconditionalizePassDbg("Need to patch jump at 0x" << std::hex << (addr - instruction->size()) << std::dec << ": " << instruction->format());
           memset(&patchloc, 0, sizeof(patchloc));
	   return;
      }
      if (bb_index >= 0) {
          unconditionalizePassLog("Warning: No branch at end of basic block " << bb_index << " at 0x" << std::hex << (addr - instruction->size()) << std::dec);
	  dumpInstructions(instructions, addrStart);
          return;
      }
    }

    void runOnFunction(ELFIO::elfio &reader, BPatch_function *function, BPatch_variableExpr *var_inject_bb, std::list<struct patchloc> &patchlocs) {
      std::set<BPatch_basicBlock*> bbs;
      BPatch_flowGraph *cfg;
      std::set<BPatch_basicBlock*>::iterator it;

      unconditionalizePassDbg("Processing function " + function->getName());
      cfg = function->getCFG();
      if (!cfg) {
          unconditionalizePassLog("Warning: Function " + function->getName() + " has no CFG");
	  return;
      }

      cfg->getAllBasicBlocks(bbs);
      for (it = bbs.begin(); it != bbs.end(); ++it) {
           runOnBasicBlock(reader, *it, var_inject_bb, patchlocs);
      }
    }

    unsigned long getJumpTargetAddr(Dyninst::InstructionAPI::Instruction::Ptr instruction, unsigned long ip) {
       std::vector<Dyninst::InstructionAPI::Operand> operands;
       std::vector<Dyninst::InstructionAPI::Operand>::iterator opIt;
       unsigned long immValue;
       bool is_pointer = false;

       instruction->getOperands(operands);
       assert(1 == operands.size());
       opIt = operands.begin();
       assert(evalConstantExpressionOrPtr(*opIt->getValue(), ip, is_pointer, immValue));
       assert(!is_pointer);
       return immValue;
    }

    void runOnFunction(ELFIO::elfio &reader, BPatch_function *function, BPatch_variableExpr *var_inject_bb, std::list<struct funcpatchloc> &funcpatchlocs, unsigned long func_id) {
      std::set<BPatch_basicBlock*> bbs;
      BPatch_flowGraph *cfg;
      std::set<BPatch_basicBlock*>::iterator bb;
      Dyninst::InstructionAPI::Instruction::Ptr instruction;
      std::vector<Dyninst::InstructionAPI::Instruction::Ptr> instructions;
      std::vector<Dyninst::InstructionAPI::Instruction::Ptr>::iterator it;
      struct funcpatchloc fpatchloc;
      unsigned long addr, addrStart, jnz_target;
      bool cmpInstFound = false, jnzFound = false, jmpFound = false;

      unconditionalizePassDbg("Processing function " + function->getName());
      cfg = function->getCFG();
      if (!cfg) {
          unconditionalizePassLog("Warning: Function " + function->getName() + " has no CFG");
          return;
      }

      memset(&fpatchloc, 0, sizeof(fpatchloc));
      cfg->getAllBasicBlocks(bbs);
      for (bb = bbs.begin(); bb != bbs.end(); ++bb) {
	addr = (*bb)->getStartAddress();
	addrStart = addr;

	get_elf_instructions(reader, *bb, addr, (*bb)->getEndAddress(), instructions);
	for (it = instructions.begin(); it != instructions.end(); ++it) {
           instruction = *it;
	   addr += instruction->size();
	   if (!instruction->isValid()) {
               unconditionalizePassLog("Warning: Invalid instruction at 0x" << std::hex << (addr - instruction->size()) << std::dec);
               dumpInstructions(instructions, addrStart);
               return;
           }
           if (!instruction->isLegalInsn()) {
               unconditionalizePassLog("Warning: Illegal instruction at 0x" << std::hex << (addr - instruction->size()) << std::dec);
               dumpInstructions(instructions, addrStart);
               return;
           }
	   if (!cmpInstFound && instructionIsFuncController(instruction, addr - instruction->size(), var_inject_bb, fpatchloc, func_id)) {
	      cmpInstFound = true;
	      continue;
	   }
	   if (fpatchloc.func_id == 0)	continue;

	   // After the cmpInst is found, look for the JNE instruction and then JMP instruction

	   if (!jnzFound && instruction->getCategory() != Dyninst::InstructionAPI::c_BranchInsn) {
               if (instructionWritesRegister(instruction, Dyninst::x86::zf)) {
                   unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb followed by ZF-modifying instruction at 0x" << std::hex << (addr - instruction->size()) << std::dec << ": " << instruction->format());
               }
               continue;
           }
	   if (!jnzFound && instruction->getOperation().getID() == e_jnz) {
		fpatchloc.mode = mode_unconditional;
	        // found the JNE instruction
	        fpatchloc.jmp_addr = addr - instruction->size();
	        fpatchloc.jmp_size = instruction->size();
	
	        unconditionalizePassDbg("getting jmp target from jne instr. at " << std::hex << fpatchloc.jmp_addr << " for function: " << func_id << std::dec);
	        jnz_target = getJumpTargetAddr(instruction, fpatchloc.jmp_addr); 
	        fpatchloc.true_block_start = (void *) addr; // addr_of(next instruction)
	        fpatchloc.true_block_size = jnz_target - addr; // excluding the JNE instruction, until the target
	        fpatchloc.false_block_start = (void *) jnz_target;

		jnzFound = true;
/*	   } 
	   if (jnzFound) {
	   	// Find out the block size of the falseblock
	        // At the end of the true block, there shall be a JMP instruction, which tells the end of the falseblock
		// So, continue until addr equals jnz_target
		if (addr != jnz_target)
			continue;
		unconditionalizePassDbg("Looking at the jmp instruction before the instruction at the JNZ target address.");
		Dyninst::InstructionAPI::Instruction::Ptr jmpInstr = *(it-1); // previous instr would be jmp instr, marking the end of true block
		assert (jmpInstr->getOperation().getID() != e_jmp);
		unsigned long jmp_target = getJumpTargetAddr(jmpInstr, addr);
		fpatchloc.false_block_size = jmp_target - (unsigned long) fpatchloc.false_block_start;
		jmpFound = true;
*/
	   } 
/*	   else {
		unconditionalizePassLog("Warning: Instruction reading edfi_inject_bb followed by unexpected type of branch instruction at 0x" << std::hex << (addr - instruction->size()) << std::dec << ": " << instruction->format());
               //dumpInstructions(instructions, addrStart);
	   }
*/
	} // end of instruction iteration
      }  // end of bb iteration

      if (!cmpInstFound || !jnzFound || !jmpFound) {
	  unconditionalizePassLog("Warning: Not all expected elements found in function: " << std::hex << func_id << std::dec);
      }
      if (0 != fpatchloc.func_id) {
         funcpatchlocs.push_back(fpatchloc);
      }
      return;
    } // end of runOnFunction

    unsigned char multibyte_nop(size_t index, size_t size) {
      size_t nop_count, nop_index, nop_size;

      /* Intel® 64 and IA-32 Architectures Software Developer’s Manual */
      /* Volume 2, Table-9. Recommended Multi-Byte Sequence of NOP Instruction */
      static unsigned char nop1[] = { 0x90 };
      static unsigned char nop2[] = { 0x66, 0x90 };
      static unsigned char nop3[] = { 0x0f, 0x1f, 0x00 };
      static unsigned char nop4[] = { 0x0f, 0x1f, 0x40, 0x00 };
      static unsigned char nop5[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
      static unsigned char nop6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
      static unsigned char nop7[] = { 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 };
      static unsigned char nop8[] = { 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
      static unsigned char nop9[] = { 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
      static unsigned char *nop[] = { nop1, nop2, nop3, nop4, nop5, nop6, nop7, nop8, nop9 };

      assert(size > 0);
      assert(index < size);

      if (size > 9) {
          nop_count = (size + 8) / 9;
	  nop_size = (size + nop_count - 1) / nop_count;
	  nop_index = index / nop_size;
	  index = index % nop_size;
	  if (nop_index + 1 == nop_count) {
              size -= nop_index * nop_size;
	  } else {
              size = nop_size;
	  }
      }

      return nop[size - 1][index];
    }

    void patch_add_byte(
      std::vector<struct patchbyte> &patchbytes,
      ELFIO::section *section,
      const char *data,
      size_t offset,
      long bb_index,
      unsigned char value_new) {
      struct patchbyte patchbyte = {
          section->get_offset() + offset,
	  bb_index,
	  data[offset],
	  value_new,
      };
      patchbytes.push_back(patchbyte);
    }

    void patch_add_nop(
      std::vector<struct patchbyte> &patchbytes,
      ELFIO::section *section,
      const char *data,
      size_t offset,
      long bb_index,
      size_t size) {
      int i;

      for (i = 0; i < size; i++) {
          patch_add_byte(
	      patchbytes,
	      section,
	      data,
	      offset + i,
              bb_index,
              multibyte_nop(i, size));
      }
    }

    void buildPatch(
      std::vector<struct patchbyte> &patchbytesgolden,
      std::vector<struct patchbyte> &patchbytesfaulty,
      std::list<struct funcpatchloc> &fpatchlocs,
      ELFIO::elfio &reader) {

      long func_id;
      size_t cmp_offset;
      const char *data;
      std::list<struct funcpatchloc>::iterator it;
      size_t jmp_offset;
      int secidx;
      ELFIO::section *section;
      ELFIO::Elf_Xword size;

      for (secidx = 0; secidx < reader.sections.size(); secidx++) {
          section = reader.sections[secidx];
          unconditionalizePassDbg("section " << secidx << " "
                "name=" << section->get_name() <<
                ", esz=0x" << std::hex << section->get_entry_size() <<
                ", addr=0x" << std::hex << section->get_address() <<
                ", sz=0x" << section->get_size() << std::dec);
          data = NULL;
	  size = section->get_size();
	  for(it = fpatchlocs.begin(); it != fpatchlocs.end(); it++) {
	       unconditionalizePassDbg("buildPatch: fpatchloc of func: " << std::hex << it->func_id);
               /* verify both instructions fit within the section */
               if (it->cmp_addr < section->get_address()) continue;
               cmp_offset = it->cmp_addr - section->get_address();
               if (cmp_offset + it->cmp_size > size) continue;

               if (it->jmp_addr < section->get_address()) continue;
               jmp_offset = it->jmp_addr - section->get_address();
               if (jmp_offset + it->jmp_size > size) continue;

               /* mark as found */
               it->found = true;

               /* obtain a copy of the segment data */
               if (!data) data = section->get_data();

               /* check whether the CMP opcode is as expected */
               if (data[cmp_offset] == (char) 0x81 && data[cmp_offset + 1] == (char) 0x3d) {
                   /* CMP Ev, Iz */
                   assert(it->cmp_size == 10);
               } else if (data[cmp_offset] == (char) 0x83 && data[cmp_offset + 1] == (char) 0x3d) {
                   /* CMP Ev, Ib */
                   assert(it->cmp_size == 7);
               } else {
                   unconditionalizePassLog("Warning: unrecognized CMP instruction at 0x" << std::hex << it->cmp_addr << std::dec);
                   continue;
               }

	       /* Compute the func_id of the cmpInst at cmp_offset */
               unsigned long func_addr, instr_addr;
               std::vector<unsigned long>::iterator func_it;
               instr_addr = (targetptr_t) section->get_address() + cmp_offset;
               func_it = std::upper_bound(func_addrs.begin(), func_addrs.end(), instr_addr); // gets the next greater element found.
               if (instr_addr < (unsigned long) func_map[*(func_it-1)].func_start) {
                    func_addr = *(func_it-2);
               } else if (instr_addr > (unsigned long) func_map[*(func_it-1)].func_end) {
                    func_addr = *(func_it);
               } else {
                    func_addr = *(func_it-1);
               }
               unconditionalizePassDbg("instr addr: " << std::hex << instr_addr << " L: " << *(func_it -1) << " this: " << *func_it << " R: " << *(func_it + 1) << "chosen :" << func_addr << std::dec);
               func_id = rdef_dwf_get_assigned_id(func_addr);
               if (func_id == 0) {
                    unconditionalizePassDbg("Warning: dwarf func_id not found for function at address: 0x" << std::hex << func_addr << std::dec);
                    continue;
               }

	       assert(it->func_id == func_id);
               /* make Jcc unconditional */
               if (it->mode == mode_unconditional &&
                   data[jmp_offset] == (char) 0x75) {
                   /* golden: JNZ rel8 -> JMP rel8 */
                   assert(it->jmp_size == 2);
                   patch_add_byte(patchbytesgolden, section, data, jmp_offset, it->func_id, 0xeb);
                   /* faulty: JNZ rel8 -> NOP */
                   patch_add_nop(patchbytesfaulty, section, data, jmp_offset, it->func_id, it->jmp_size);
               } else if (it->mode == mode_nop &&
                   data[jmp_offset] == (char) 0x74) {
                   /* golden: JZ rel8 -> NOP */
                   assert(it->jmp_size == 2);
                   patch_add_nop(patchbytesgolden, section, data, jmp_offset, it->func_id, it->jmp_size);
                   /* faulty: JZ rel8 -> JMP rel8 */
                   patch_add_byte(patchbytesfaulty, section, data, jmp_offset, it->func_id, 0xeb);
               } else if (it->mode == mode_unconditional &&
                   data[jmp_offset] == (char) 0x0f &&
                   data[jmp_offset + 1] == (char) 0x85) {
                   /* golden: JNZ rel32 -> NOP; JMP rel32 */
                   assert(it->jmp_size == 6);
                   patch_add_byte(patchbytesgolden, section, data, jmp_offset, it->func_id, 0x90);
                   patch_add_byte(patchbytesgolden, section, data, jmp_offset + 1, it->func_id, 0xe9);
                   /* faulty: JNZ rel32 -> NOP; JMP rel32 */
                   patch_add_nop(patchbytesfaulty, section, data, jmp_offset, it->func_id, it->jmp_size);
               } else if (it->mode == mode_nop &&
                   data[jmp_offset] == (char) 0x0f &&
                   data[jmp_offset + 1] == (char) 0x84) {
                   /* golden: JZ rel32 -> NOP */
                   assert(it->jmp_size == 6);
                   patch_add_nop(patchbytesgolden, section, data, jmp_offset, it->func_id, it->jmp_size);
                   /* faulty: JZ rel32 -> NOP; JMP rel32 */
                   patch_add_byte(patchbytesfaulty, section, data, jmp_offset, it->func_id, 0x90);
                   patch_add_byte(patchbytesfaulty, section, data, jmp_offset + 1, it->func_id, 0xe9);
               } else {
                   unconditionalizePassLog("Warning: unrecognized JMP instruction at 0x" << std::hex << it->jmp_addr << std::dec);
                   break;
               }

               /* golden&faulty: NOP out compare (let's hope flags are not relied on) */
               patch_add_nop(patchbytesgolden, section, data, cmp_offset, it->func_id, it->cmp_size);
               patch_add_nop(patchbytesfaulty, section, data, cmp_offset, it->func_id, it->cmp_size);
	  }
      }

      for (it = fpatchlocs.begin(); it != fpatchlocs.end(); ++it) {
          unconditionalizePassDbg("patchloc cmp_addr: " << std::hex << it->cmp_addr << std::dec);
          if (it->found) continue;
          unconditionalizePassLog("Warning: instructions of " << std::hex << it->func_id << "at 0x" << it->cmp_addr << " and 0x" << it->jmp_addr << std::dec << " not found in any section");
      }
      unconditionalizePassDbg("Building patch (function-wise) - done.");
    }

    void buildPatch(
      std::vector<struct patchbyte> &patchbytesgolden,
      std::vector<struct patchbyte> &patchbytesfaulty,
      std::list<struct patchloc> &patchlocs,
      ELFIO::elfio &reader) {
      long bb_index;
      long func_id;
      size_t cmp_offset;
      const char *data;
      std::list<struct patchloc>::iterator it;
      size_t jmp_offset;
      int secidx;
      ELFIO::section *section;
      ELFIO::Elf_Xword size;

      for (secidx = 0; secidx < reader.sections.size(); secidx++) {
	  section = reader.sections[secidx];
          unconditionalizePassDbg("section " << secidx << " "
		"name=" << section->get_name() <<
		", esz=0x" << std::hex << section->get_entry_size() <<
		", addr=0x" << std::hex << section->get_address() <<
		", sz=0x" << section->get_size() << std::dec);
	  data = NULL;
          for (it = patchlocs.begin(); it != patchlocs.end(); ++it) {
	       size = section->get_size();

	       /* verify both instructions fit within the section */
               if (it->cmp_addr < section->get_address()) continue;
	       cmp_offset = it->cmp_addr - section->get_address();
	       if (cmp_offset + it->cmp_size > size) continue;

               if (it->jmp_addr < section->get_address()) continue;
	       jmp_offset = it->jmp_addr - section->get_address();
	       if (jmp_offset + it->jmp_size > size) continue;

	       /* mark as found */
	       it->found = true;

	       /* obtain a copy of the segment data */
	       if (!data) data = section->get_data();

	       /* check whether the CMP opcode is as expected */
	       if (data[cmp_offset] == (char) 0x81 && data[cmp_offset + 1] == (char) 0x3d) {
		   /* CMP Ev, Iz */
		   assert(it->cmp_size == 10);
		   bb_index = *(uint32_t *) (data + cmp_offset + 6);
	       } else if (data[cmp_offset] == (char) 0x83 && data[cmp_offset + 1] == (char) 0x3d) {
		   /* CMP Ev, Ib */
		   assert(it->cmp_size == 7);
		   bb_index = *(int8_t *) (data + cmp_offset + 6);
	       } else {
                   unconditionalizePassLog("Warning: unrecognized CMP instruction at 0x" << std::hex << it->cmp_addr << std::dec);
		   continue;
	       }

	       if (clOptVarsPerFunction) {
		   unsigned long func_addr, instr_addr;
		   std::vector<unsigned long>::iterator func_it;
		   instr_addr = (targetptr_t) section->get_address() + cmp_offset;
		   func_it = std::upper_bound(func_addrs.begin(), func_addrs.end(), instr_addr); // gets the next greater element found.
		   //func_addr = func_it > func_addrs.begin() ? (*(func_it - 1)) : func_addrs.begin();
		   if (instr_addr < (unsigned long) func_map[*(func_it-1)].func_start) {
			func_addr = *(func_it-2);
		   } else if (instr_addr > (unsigned long) func_map[*(func_it-1)].func_end) {
			func_addr = *(func_it);
		   } else {
		   	func_addr = *(func_it-1);
		   }
		   unconditionalizePassDbg("instr addr: " << std::hex << instr_addr << " L: " << *(func_it -1) << " this: " << *func_it << " R: " << *(func_it + 1) << "chosen :" << func_addr << std::dec);

		   func_id = rdef_dwf_get_assigned_id(func_addr);
		   if (func_id == 0) {
			unconditionalizePassDbg("TODO fix: dwarf func_id not found for function at address: 0x" << std::hex << func_addr << std::dec);
			continue;
		   }
		   bb_index = func_id;
		}
		// We re-use bb_index itself to store func_id, in case of per-function control variables.
	       unconditionalizePassDbg("patchloc: " << std:: hex << " bb_index: " << it->bb_index << 
	       			       " func_id/bb_index fetched: " << bb_index << std::dec);
  	        assert(bb_index == it->bb_index);

	       /* make Jcc unconditional */
	       if (it->mode == mode_unconditional &&
                   data[jmp_offset] == (char) 0x75) {
		   /* golden: JNZ rel8 -> JMP rel8 */
		   assert(it->jmp_size == 2);
                   patch_add_byte(patchbytesgolden, section, data, jmp_offset, it->bb_index, 0xeb);
		   /* faulty: JNZ rel8 -> NOP */
	           patch_add_nop(patchbytesfaulty, section, data, jmp_offset, it->bb_index, it->jmp_size);
	       } else if (it->mode == mode_nop &&
                   data[jmp_offset] == (char) 0x74) {
		   /* golden: JZ rel8 -> NOP */
		   assert(it->jmp_size == 2);
	           patch_add_nop(patchbytesgolden, section, data, jmp_offset, it->bb_index, it->jmp_size);
		   /* faulty: JZ rel8 -> JMP rel8 */
                   patch_add_byte(patchbytesfaulty, section, data, jmp_offset, it->bb_index, 0xeb);
	       } else if (it->mode == mode_unconditional &&
                   data[jmp_offset] == (char) 0x0f &&
                   data[jmp_offset + 1] == (char) 0x85) {
		   /* golden: JNZ rel32 -> NOP; JMP rel32 */
		   assert(it->jmp_size == 6);
                   patch_add_byte(patchbytesgolden, section, data, jmp_offset, it->bb_index, 0x90);
                   patch_add_byte(patchbytesgolden, section, data, jmp_offset + 1, it->bb_index, 0xe9);
		   /* faulty: JNZ rel32 -> NOP; JMP rel32 */
	           patch_add_nop(patchbytesfaulty, section, data, jmp_offset, it->bb_index, it->jmp_size);
	       } else if (it->mode == mode_nop &&
                   data[jmp_offset] == (char) 0x0f &&
                   data[jmp_offset + 1] == (char) 0x84) {
		   /* golden: JZ rel32 -> NOP */
		   assert(it->jmp_size == 6);
	           patch_add_nop(patchbytesgolden, section, data, jmp_offset, it->bb_index, it->jmp_size);
		   /* faulty: JZ rel32 -> NOP; JMP rel32 */
                   patch_add_byte(patchbytesfaulty, section, data, jmp_offset, it->bb_index, 0x90);
                   patch_add_byte(patchbytesfaulty, section, data, jmp_offset + 1, it->bb_index, 0xe9);
	       } else {
                   unconditionalizePassLog("Warning: unrecognized JMP instruction at 0x" << std::hex << it->jmp_addr << std::dec);
		   break;
	       }

	       /* golden&faulty: NOP out compare (let's hope flags are not relied on) */
	       patch_add_nop(patchbytesgolden, section, data, cmp_offset, it->bb_index, it->cmp_size);
	       patch_add_nop(patchbytesfaulty, section, data, cmp_offset, it->bb_index, it->cmp_size);
          }
      }

      for (it = patchlocs.begin(); it != patchlocs.end(); ++it) {
	  unconditionalizePassDbg("patchloc cmp_addr: " << std::hex << it->cmp_addr << std::dec);
          if (it->found) continue;
          unconditionalizePassLog("Warning: instructions at 0x" << std::hex << it->cmp_addr << " and 0x" << it->jmp_addr << std::dec << " not found in any section");
      }
      unconditionalizePassDbg("Building patch - done.");
    }

    void storePatch(std::vector<struct patchbyte> &patchbytesgolden,
      std::vector<struct patchbyte> &patchbytesfaulty,
      std::string pathout) {
      uint32_t bbcount, bbcountgolden, bbcountfaulty;
      long bb_index;
      struct ucpatch_byte byte;
      int indexf, indexg, writebytes;
      struct ucpatch_location location;
      uint32_t offset;
      struct patchbyte patchbyte;
      std::string pathpatch = pathout + ".ucpatch";
      int which;

      unconditionalizePassDbg("Saving patch: " << pathpatch);
      std::ofstream file_out(pathpatch.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);

      std::sort(patchbytesgolden.begin(), patchbytesgolden.end(), compare_patchbyte_bbindex);
      std::sort(patchbytesfaulty.begin(), patchbytesfaulty.end(), compare_patchbyte_bbindex);

      /* write bbcount (may be an underestimate, includes only patched bbs) */
      bbcountgolden = (patchbytesgolden.size() > 0) ? (patchbytesgolden[patchbytesgolden.size() - 1].bb_index + 1) : 0;
      bbcountfaulty = (patchbytesfaulty.size() > 0) ? (patchbytesfaulty[patchbytesfaulty.size() - 1].bb_index + 1) : 0;
      bbcount = (bbcountgolden > bbcountfaulty) ? bbcountgolden : bbcountfaulty;
      file_out.write((char *) &bbcount, sizeof(bbcount));

      /* write locations */
      memset(&location, 0, sizeof(location));
      memset(&byte, 0, sizeof(byte));
      for (writebytes = 0; writebytes <= 1; writebytes++) {
	  bb_index = -1;
          indexg = 0;
          indexf = 0;
          offset = sizeof(bbcount) + sizeof(location) * bbcount;
	  for (;;) {
              /* which of the two has the next patch byte? */
	      if (indexg < patchbytesgolden.size()) {
	          if (indexf < patchbytesfaulty.size()) {
	              which = compare_patchbyte_bbindex_int(patchbytesgolden[indexg], patchbytesfaulty[indexf]);
	          } else {
                      which = -1;
	          }
	      } else {
	          if (indexf < patchbytesfaulty.size()) {
	              which = 1;
	          } else {
		      break;
	          }
	      }

              /* write location */
	      patchbyte = (which > 0) ? patchbytesfaulty[indexf] : patchbytesgolden[indexg];
	      assert(bb_index <= patchbyte.bb_index);
	      while (bb_index < patchbyte.bb_index) {
	          location.count = offset - location.offset;
                  if (!writebytes && bb_index >= 0) file_out.write((char *) &location, sizeof(location));
		  location.offset = offset;
		  bb_index++;
              }

              /* write bytes */
	      if (writebytes) {
                  byte.offset = patchbyte.offset;
                  byte.value_orig = patchbyte.value_orig;
                  byte.value_golden = (which <= 0) ? patchbytesgolden[indexg].value_new : patchbyte.value_orig;
                  byte.value_faulty = (which >= 0) ? patchbytesfaulty[indexf].value_new : patchbyte.value_orig;
                  file_out.write((char *) &byte, sizeof(byte));
	      }

	      if (which <= 0) indexg++;
	      if (which >= 0) indexf++;
	      offset += sizeof(byte);
	  }
          location.count = offset - location.offset;
          if (!writebytes && bb_index >= 0) file_out.write((char *) &location, sizeof(location));
      }
    }

    void applyPatch(std::string path, std::string pathout,
      std::vector<struct patchbyte> &patchbytes) {
      int c;
      ELFIO::Elf64_Off file_offset = 0;
      int patchbyte_index = 0;

      unconditionalizePassDbg("Saving patched ELF file: " << pathout);
      std::ifstream file_in(path.c_str(), std::ios::in | std::ios::binary);
      std::ofstream file_out(pathout.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);

      std::sort(patchbytes.begin(), patchbytes.end(), compare_patchbyte_offset);

      while ((c = file_in.get()) != EOF) {
	  /* apply patch is it is applicable to the current byte */
	  if (patchbyte_index < patchbytes.size() && patchbytes[patchbyte_index].offset == file_offset) {
              assert(c == patchbytes[patchbyte_index].value_orig);
	      c = patchbytes[patchbyte_index].value_new;
	      patchbyte_index++;
	      assert(patchbyte_index >= patchbytes.size() || patchbytes[patchbyte_index].offset > file_offset);
	  }
	  /* copy the (possibly changed) byte to the output file */
          file_out.put(c);
	  file_offset++;
      }
    }

    bool updateImage(ELFIO::elfio &reader, std::string path, std::string pathout,
      std::list<struct funcpatchloc> &fpatchlocs) {
      std::vector<struct patchbyte> patchbytesfaulty;
      std::vector<struct patchbyte> patchbytesgolden;

      unconditionalizePassDbg("[perFuncVars] Number of patch locations found: " << fpatchlocs.size());

      buildPatch(patchbytesgolden, patchbytesfaulty, fpatchlocs, reader);
      storePatch(patchbytesgolden, patchbytesfaulty, pathout);
      applyPatch(path, pathout, patchbytesgolden);

      return true;
    }


    bool updateImage(ELFIO::elfio &reader, std::string path, std::string pathout,
      std::list<struct patchloc> &patchlocs) {
      std::vector<struct patchbyte> patchbytesfaulty;
      std::vector<struct patchbyte> patchbytesgolden;

      unconditionalizePassDbg("Number of patch locations found: " << patchlocs.size());

      buildPatch(patchbytesgolden, patchbytesfaulty, patchlocs, reader);
      storePatch(patchbytesgolden, patchbytesfaulty, pathout);
      applyPatch(path, pathout, patchbytesgolden);

      return true;
    }

    bool skipSection(ELFIO::elfio &reader, unsigned long func_addr) {
      int secidx;
      ELFIO::section *section;
      static ELFIO::section *skipSection = NULL;

      if (NULL == skipSection &&  (std::string(clOptSkipSection).compare("") != 0)) {
         for (secidx = 0; secidx < reader.sections.size(); secidx++) {
             section = reader.sections[secidx];
             if (0 == std::string(section->get_name()).compare(clOptSkipSection)) {
                  skipSection = section;
		  break;
             }
         }
      }
      if (NULL == skipSection) {
          return false;
      }
      if (func_addr >= skipSection->get_address() &&
          func_addr < skipSection->get_address() + skipSection->get_size()) {
              unconditionalizePassDbg("Function Address  0x" << std::hex << func_addr << std::dec << " is in section: " << skipSection->get_name() << ". Skipping.");
              return true;
          }
      return false;
    }

  public:
    static char ID;
    UnconditionalizePass() : ModulePass(ID) {}

    virtual bool runOnModule(void *M) {
      unconditionalizePassLog("ERROR: framework invoked wrong UnconditionalizePass::runOnModule overload");
      return false;
    }

    virtual bool runOnModule(void *M, std::string path, std::string pathout,
      bool &outputWritten) {
      BPatch_addressSpace *as = (BPatch_addressSpace*) M;
      std::vector<BPatch_function *> *functions;
      std::vector<BPatch_function *>::iterator it;
      BPatch_image *image;
      BPatch_binaryEdit *binEdit = dynamic_cast<BPatch_binaryEdit*>(as);
      bool isBinEdit = binEdit != NULL;
      std::list<struct patchloc> patchlocs;
      std::list<struct funcpatchloc> fpatchlocs;
      ELFIO::elfio reader;
      BPatch_variableExpr *var_global;
      BPatch_variableExpr *var_inject_bb;
      BPatch_Vector<BPatch_statement> func_src_lines;
      unsigned long func_addr;
      std::string func_name;
      static bool rdef_dwarfer_initialized = false;

      if (!isBinEdit) {
          unconditionalizePassLog("ERROR: Binary edit not supported by Unconditionalize Pass");
	  return false;
      }
      unconditionalizePassLog("Running (binary)...");
      unconditionalizePassDbg("Debug mode enabled!");

      if (0 == std::string(clOptGVarName).compare("")) {
          unconditionalizePassLog("ERROR: Global variable name not specified.");
          return false;
      }
      unconditionalizePassDbg("Finding variable: " << std::string(clOptGVarName));
      image = as->getImage();
      var_global = image->findVariable(std::string(clOptGVarName).c_str());
      if (!var_global) {
          unconditionalizePassLog("ERROR: Global variable " << std::string(clOptGVarName) << " does not exist, did you use the -fault-unconditionalize EDFI option?");
          return false;
      }
      unconditionalizePassDbg(std::string(clOptGVarName) << "=0x" << hex << (unsigned long) var_global->getBaseAddr() << std::dec);

      unconditionalizePassDbg("Loading ELF file for patching: " << path);
      if (!reader.load(path)) {
          unconditionalizePassLog("ERROR: Cannot open ELF file " << path);
	  return false;
      }

      unconditionalizePassDbg("Processing functions");
      functions = image->getProcedures(true);
      var_inject_bb = var_global; // by default, point this to the global variable

      if (clOptVarsPerFunction) {
      	for (it = functions->begin(); it != functions->end(); ++it) {
                if (!rdef_dwarfer_initialized) {
                    assert (0 == rdef_dwf_load(path.c_str()));
                    rdef_dwarfer_initialized = true;
                }
               // Access function ID and get the variable corresponding to this function to pass it on to the runOnFunction function call
   	       // Use image->getSourceLines to get BPatch_statement vector and use BPatch_statement->lineOffset() to get the col. number 
               //which has the function ID that we pass on from our prev. Reflex instrumentation.

               // Skip for functions belonging to special sections in the binary (like rdefender section)
               func_addr = (unsigned long)(*it)->getBaseAddr();
               func_name = (*it)->getName();
               assert(0 != func_addr && "func_addr is 0x0");
               if(skipSection(reader, func_addr)) {
                   continue;
               }
               BPatch_Vector<BPatch_point *> func_entryPoints;
               (*it)->getEntryPoints(func_entryPoints);
               void  *func_start, *func_end;
               assert((*it)->getAddressRange(func_start, func_end));
               assert(func_start <= func_end);

               bool linesFound = false;
               unsigned func_id = 0;
	       for(unsigned long i = (unsigned long)func_start; i < (unsigned long)func_end; i++) {
                   func_addr = i;
//                   unconditionalizePassDbg("Looking for func addr: 0x" << std::hex << func_addr << std::dec << "(" << func_name << ")");
                   if ( 0 < (func_id = rdef_dwf_get_assigned_id(func_addr))) {
                       linesFound = true;
		       unconditionalizePassDbg("func_addr: " << std::hex << func_addr << " func name: " << func_name << " func_id: " << func_id << std::dec );
                            break;
                   }
	       }
               unconditionalizePassDbg("var_inject_bb: " << std::hex << var_inject_bb->getBaseAddr() << "func_id: " << func_id << std::dec);
	       if (!linesFound) {
		  unconditionalizePassDbg("WARNING: unable to locate func-id for function: " << func_name);
		  continue;
	       }
	       struct funcboundary fmap;
	       func_addrs.push_back(func_addr);
	       fmap = { func_start, func_end };
	       func_map.insert(std::pair<unsigned long, struct funcboundary>(func_addr, fmap));
	       memset(&fmap, 0, sizeof(fmap));
	       runOnFunction(reader, *it, var_inject_bb, fpatchlocs, (unsigned long)func_id);
	  } // end of for iterating on functions

	  std::vector<unsigned long>::iterator new_last;
	  std::sort(func_addrs.begin(), func_addrs.end());
	  new_last = std::unique(func_addrs.begin(), func_addrs.end());
	  func_addrs.erase(new_last, func_addrs.end());

      	  remove_duplicate_patchlocs(fpatchlocs);
	  if (!updateImage(reader, path, pathout, fpatchlocs)) return false;

      } else {
      	for (it = functions->begin(); it != functions->end(); ++it) {
		runOnFunction(reader, *it, var_inject_bb, patchlocs);
	}
      	remove_duplicate_patchlocs(patchlocs);
        if (!updateImage(reader, path, pathout, patchlocs)) return false;
      }

      outputWritten = true;
      return true;
    }
  };

}

char UnconditionalizePass::ID = 0;
RegisterPass<UnconditionalizePass> MP("unconditionalize", "Unconditionalize Pass");

