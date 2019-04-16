CC=clang
INCLUDES= -I../../include -L/usr/local/lib/x86_64-linux-gnu
CFLAGS+= $(INCLUDES)
LIBS= -ldwarf -lelf -lipt -lxed
ADDL_SRCS=

# Note: libdwarf-dev package is required 
ifeq ($(NOPRINT), 1)
CFLAGS+= -DNOPRINT
endif
ifeq ($(ELF), 1)
CFLAGS+= -DFEATURE_ELF 
INCLUDES+= -I../external/processor-trace/ptxed/include/
ADDL_SRCS= ../external/processor-trace/ptxed/src/load_elf.c
endif

all:		diagnoser

dwarfreader:	DwarfReader.h DwarfReader.cpp
	 $(CC) $(CFLAGS) DwarfReader.cpp -o dwarfreader $(LIBS)

diagnoser:	rdef_pt.h rdef_pt.c rdef_dwarf.h rdef_dwarf.c rdef_diagnoser.h rdef_diagnoser.c \
		rdef_xed.h rdef_xed.c rdef_sideband.h rdef_sideband.c rdef_sideband_elf.h rdef_sideband_elf.c \
		rdef_sideband_symtab.h rdef_sideband_symtab.c

		$(CC)  $(CFLAGS) rdef_pt.c rdef_dwarf.c rdef_diagnoser.c rdef_xed.c rdef_sideband.c \
				 rdef_sideband_elf.c rdef_sideband_symtab.c \
				 $(ADDL_SRCS) $(LIBS) -o diagnoser 

install:	diagnoser
		cp diagnoser ${HOME}/scratchspace/diagnoser-testing

clean:
	rm -f dwarfreader diagnoser *.o

