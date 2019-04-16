#ifndef DWARFREADER_H
#define DWARFREADER_H

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <map>
#include "dwarf.h"
#include "libdwarf.h"
#include <sys/types.h>
#include <iostream>

#define E_OK	0
#define E_ERROR	1

using namespace std;

class DwarfReader
{
public:
  DwarfReader();
  ~DwarfReader();
  bool initialize(char *binFileName);
  unsigned getBBID(unsigned long instrAddr);
  void printInfo();

private:
  int binFD;
  // std::vector<FunctionInfo> functions;
  // std::map<std::string, unsigned long> mFunctionAddrMap;
  std::map<unsigned long, long> mAddrBBIDMap;

  Dwarf_Die get_cu_die(Dwarf_Debug dbg, int *pres);

};

DwarfReader::DwarfReader()
{

}

DwarfReader::~DwarfReader()
{

}

bool DwarfReader::initialize(char *binFileName)
{
  int retval = false;

  binFD = open(binFileName, O_RDONLY);
  if (binFD < 0)
  {
    cerr << "Error: Failure attempting to open " << binFileName << "\n";
      return false;
  }

  /* initialize dwarf structures */
  Dwarf_Debug dbg;
  Dwarf_Error error;
  Dwarf_Handler errhand = 0;
  Dwarf_Ptr errarg = 0;
  int res = 0;
  res = dwarf_init(binFD, DW_DLC_READ, errhand, errarg, &dbg, &error);
  if (res != DW_DLV_OK) {
      cerr << "Error: Cannot dwarf_init\n";
      return false;
  }

  Dwarf_Die cu_die = get_cu_die(dbg, &res);
  if (!cu_die) {
    cerr << "Failure getting cu_die\n";
      if(res == DW_DLV_ERROR)
          return false;
      else
          goto finish;
  }

  Dwarf_Signed cnt;
  Dwarf_Line *linebuf;
  int sres;
  if ((sres = dwarf_srclines(cu_die, &linebuf,&cnt, &error)) != DW_DLV_OK)
  {
    return false;
  }

  cout << "Num srclines fetched: " << cnt << "\n";

  for(int i=0; i < cnt; i++)
  {
    Dwarf_Line currLine = linebuf[i];
    Dwarf_Addr lineAddr;
    Dwarf_Signed colNum;
    if (DW_DLV_OK != dwarf_lineaddr(currLine, &lineAddr, &error))
    {
      return false;
    }
    if (DW_DLV_OK != dwarf_lineoff(currLine, &colNum, &error))
    {
      return false;
    }
    if ( 0 == mAddrBBIDMap.count(lineAddr))
    {
      mAddrBBIDMap.insert(std::pair<unsigned long, long>(lineAddr, colNum));
    }
  }

  retval = true;

  // Clean up Dwarf related structures
  dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);

  finish:
  res = dwarf_finish(dbg, &error);
  if (res != DW_DLV_OK) {
      fprintf(stderr, "Error: Cannot dwarf_finish\n");
      exit(E_ERROR);
  }
  return retval;
}

unsigned DwarfReader::getBBID(unsigned long addr)
{
  if (mAddrBBIDMap.count(addr) == 0)
  {
    return 0;  // BBID never will be zero and valid.
  }
  return (*(mAddrBBIDMap.find(addr))).second;
}

void DwarfReader::printInfo()
{
  for (std::map<unsigned long, long>::iterator mI = mAddrBBIDMap.begin(), mE = mAddrBBIDMap.end(); mI != mE; mI++)
  {
    cout << "addr: " << std::hex << mI->first << "\tBB: " << std::dec << mI->second << "\n";
  }
}

Dwarf_Die DwarfReader::get_cu_die(Dwarf_Debug dbg, int *pres)
{
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Unsigned next_cu_header = 0;
    Dwarf_Error error;
    int cu_number = 0;
    int res = *pres;

    Dwarf_Die cu_die = 0;
    for ( ;; ++cu_number) {
        Dwarf_Die no_die = 0;
        // Dwarf_Die cu_die;
        res = DW_DLV_ERROR;
        res = dwarf_next_cu_header(dbg, &cu_header_length,
            &version_stamp, &abbrev_offset, &address_size,
            &next_cu_header, &error);
        if (res == DW_DLV_ERROR) {
            fprintf(stderr, "Error in dwarf_next_cu_header\n");
            exit(E_ERROR);
        }
        if (res == DW_DLV_NO_ENTRY) {
            /* Done. */
            cout << "DW_DLV_NO_ENTRY\n" ;
            return cu_die;
        }
        /* The CU will have a single sibling, a cu_die. */
        res = dwarf_siblingof(dbg, no_die, &cu_die, &error);
        if (res == DW_DLV_ERROR) {
            fprintf(stderr, "Error in dwarf_siblingof on CU die \n");
            exit(E_ERROR);
        }
        if (res == DW_DLV_NO_ENTRY) {
            /* Impossible case. */
            fprintf(stderr, "no entry! in dwarf_siblingof on CU die \n");
            exit(E_ERROR);
        }
        cout << "cu_number = " << cu_number << "\n";

        Dwarf_Half tagval;
        res = dwarf_tag(cu_die, &tagval, &error);
        if (res == DW_DLV_OK && tagval == DW_TAG_compile_unit)
        {
          cout << "cu_die has DW_TAG_compile_unit tag.\n";
        }
        return cu_die;
    }
}


#endif
