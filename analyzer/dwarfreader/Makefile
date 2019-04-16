CXX=clang++
INCLUDES= -I../include -L/usr/local/lib/x86_64-linux-gnu
CFLAGS+= $(INCLUDES)
LIBS= -ldwarf -lelf -lipt -lxed
ADDL_SRCS=

all:	dwarfreader

dwarfreader:    DwarfReader.h DwarfReader.cpp
	$(CXX) $(CFLAGS) DwarfReader.cpp -o dwarfreader $(LIBS)

clean:	
	rm -f dwarfreader *.o
