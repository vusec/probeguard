#include "DwarfReader.h"

void print_usage(char *progname)
{
  printf("Usage: \n");
  printf("%s <elf binary file path>\n", progname);
  
  printf("\n Reads DWARF source location information to map instruction addresses to basic block IDs\n");
  return;
}

int main(int argc, char **argv)
{
  if (argc <= 1)
  {
    print_usage(argv[0]);
    return 1;
  }
  char *filename = argv[1];
  DwarfReader  *dwarfReader = new DwarfReader();
  if (false == dwarfReader->initialize(filename))
  {
    cerr << "Failure initializing the DwarfReader.\n";
    return -1;
  }
  cout << "dwarfReader initialized.\n";
  dwarfReader->printInfo();
  return 0;
}
