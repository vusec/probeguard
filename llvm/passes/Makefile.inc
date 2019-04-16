include $(ROOT)/Makefile.inc
include $(ROOT)/llvm/Makefile.inc

CFLAGS  += $(CXXFLAGS) -Wno-long-long -Wall -W -Wno-unused-parameter -Wwrite-strings -DHAVE_EXCEPTIONS=0
CFLAGS  += $(shell $(LLVMPREFIX)/bin/llvm-config --cxxflags) -g -DLLVM_VERSION=$(LLVM_VERSION)
LDFLAGS += $(shell $(LLVMPREFIX)/bin/llvm-config --ldflags) -L$(LLVMLIB)

LLVM_VERSION_HAS_REGEX = $(shell expr $(LLVM_VERSION) \>= 31)
ifeq ($(LLVM_VERSION_HAS_REGEX),0)
LIBS += -lLLVMRegex2.8
endif

PASSLIBNAME =$(PASSNAME).so

HEADERS += $(wildcard $(LLVMINC)/*.h) $(wildcard ../include/*.h) $(wildcard ../include/common/*.h) $(wildcard ../include/$(PASSNAME)/*.h)

INCLUDES += -I../include

all: $(PASSLIBNAME)

$(PASSLIBNAME): $(OBJS)
	$(QUIET) $(ECHO) "  [LINK] $@"
	$(QUIET) $(CXX) $(CFLAGS) -shared -o $@ $(CPPS) $(OBJS) $(LDFLAGS) $(LIBS)

%.o: %.cpp $(HEADERS)
	$(QUIET) $(ECHO)  "  [C++] $<"
	$(QUIET) $(CXX) $(CFLAGS) $(INCLUDES) -c -o $@ $<

install: $(INSTALL_DIR)/$(PASSLIBNAME)

$(INSTALL_DIR)/$(PASSLIBNAME): $(PASSLIBNAME)
	$(QUIET) $(ECHO) "  [INSTALL] $< -> $@"
	$(QUIET) install -c -D -m 744 $? $@

clean:
	$(QUIET) $(ECHO) "  [RM] $(OBJS) $(PASSLIBNAME)"
	$(QUIET) rm -f $(OBJS) $(PASSLIBNAME)

distclean: clean
	$(QUIET) $(ECHO)  "  [RM] $(INSTALL_DIR)/$(PASSLIBNAME)"
	$(QUIET) rm -f $(INSTALL_DIR)/$(PASSLIBNAME)





