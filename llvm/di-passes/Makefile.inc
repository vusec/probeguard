include $(ROOT)/Makefile.inc
include $(ROOT)/llvm/Makefile.inc
include ../Makefile.def.inc

CC=gcc
CXX=g++

PASSLIBNAME =$(PASSNAME).di

HEADERS += $(wildcard $(LLVMINC)/common/opt/*.h) $(wildcard ../include/*.h) $(wildcard ../include/common/*.h) $(wildcard ../include/$(PASSNAME)/*.h)

all: $(PASSLIBNAME) $(EXTRA_TARGETS)

$(PASSLIBNAME): $(OBJS)
	$(QUIET) $(ECHO) "  [LINK] $@"
	$(QUIET) $(CXX) $(CFLAGS) $(FFLAGS) -shared -o $@ $(CPPS) $(OBJS) $(LDFLAGS) $(LIBS)

%.o: %.cpp $(HEADERS)
#	echo $(FFLAGS)
	$(QUIET) $(ECHO)  "  [C++] $<"
	$(QUIET) $(CXX) $(CFLAGS) $(FFLAGS) $(INCLUDES) -c -o $@ $<

install: $(INSTALL_DIR)/$(PASSLIBNAME)

$(INSTALL_DIR)/$(PASSLIBNAME): $(PASSLIBNAME)
	$(QUIET) $(ECHO) "  [INSTALL] $< -> $@"
	$(QUIET) install -c -D -m 744 $? $@

clean:
	$(QUIET) $(ECHO) "  [RM] $(OBJS) $(PASSLIBNAME) $(CLEANUP)"
	$(QUIET) rm -f $(OBJS) $(PASSLIBNAME) $(CLEANUP)

distclean: clean
	$(QUIET) $(ECHO)  "  [RM] $(INSTALL_DIR)/$(PASSLIBNAME)"
	$(QUIET) rm -f $(INSTALL_DIR)/$(PASSLIBNAME)





