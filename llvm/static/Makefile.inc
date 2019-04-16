include $(ROOT)/llvm/Makefile.inc

MODULE_NAME=$(MODULE).bcc

CFLAGS += $(CXXFLAGS) -Wall -g -Wno-long-long

HAVE_NOCONSTRUCTOR_PRIORITY = $(shell expr $(LLVM_VERSION) \>= 30)
ifeq ($(HAVE_NOCONSTRUCTOR_PRIORITY),0)
CFLAGS += -DHAVE_NOCONSTRUCTOR_PRIORITY=1 
endif

# are we using liboverride?
ifdef OBJS-OVERRIDE
include $(ROOT)/llvm/shared/common/liboverride/Makefile.inc
CLEAN_OVERRIDES= clean_overrides
else
CLEAN_OVERRIDES=
endif

ifeq ($(USE_SECTIONIFY),YES)
LOPT_FLAGS+=-load=$(LLVMSECTIONIFY_SO) -sectionify -sectionify-no-override -sectionify-data-section-map=$(SECTIONIFY_DATA_SECTION_MAP) -sectionify-function-section-map=$(SECTIONIFY_FUNCTION_SECTION_MAP)
ifeq (SECTIONIFY_NO_OVERRIDE,YES)
LOPT_FLAGS+=-sectionify-no-override
endif
endif

SKIP=NO

ifeq ($(SKIP),NO)

ifeq ($(HAVE_LLVM),1)
$(MODULE_NAME): $(OBJS) $(HEADERS) $(COMMON_BCCS)
	$(QUIET) $(ECHO) "  [GOLD_LINK] $@.o"
	$(QUIET) $(LLVMGOLD_CC) $(CFLAGS) $(LLVMGOLD_CFLAGS) $(LLVMGOLD_LDFLAGS) -shared -o $@.o $(OBJS) $(COMMON_BCCS)
	$(QUIET) $(ECHO) "  [OPT] $@"
	$(QUIET) $(LLVMPREFIX)/bin/opt $(LOPT_FLAGS) -o $@ $@.o.bc
else
$(MODULE_NAME): $(OBJS) $(HEADERS) $(COMMON_BCCS)
	$(QUIET) $(ECHO) "  [LINK] $@"
	$(QUIET) $(LLVMGOLD_CC) $(CFLAGS) $(LLVMGOLD_CFLAGS) $(LLVMGOLD_LDFLAGS) -shared -o $@ $(OBJS) $(COMMON_BCCS)
endif

all: $(MODULE_NAME)

%.o: %.c $(HEADERS)
	$(QUIET) $(ECHO) "  [GOLD_CC] $<"
	$(QUIET) $(LLVMGOLD_CC) $(CFLAGS)  $(LLVMGOLD_CFLAGS) $(INCLUDES) $(INCLUDES_$<) -c -o $@ $<

install: $(INSTALL_DIR)/$(MODULE_NAME)

$(INSTALL_DIR)/$(MODULE_NAME): $(MODULE_NAME)
	install -c -D -m 744 $? $@

clean_overrides:
	$(QUIET) $(ECHO) "  [RM] $(LIBOVERRIDE_FILES)"
	$(QUIET) cd override && rm -f $(LIBOVERRIDE_FILES)

clean: $(EXTRA_CLEAN) $(CLEAN_OVERRIDES)
	$(QUIET) $(ECHO) "  [RM] *.BCC *.bcc *.bc *.BCL *.BCL.sh *.bcl $(OBJS) *.s $(COMMON_BCCS)"
	$(QUIET) rm -f *.BCC *.bcc *.bc *.BCL *.BCL.sh *.bcl *.o $(OBJS) *.s $(COMMON_BCCS)

distclean: clean
	$(QUIET) $(ECHO) "  [RM] $(INSTALL_DIR)/$(MODULE_NAME)"
	$(QUIET) rm -f $(INSTALL_DIR)/$(MODULE_NAME)

else

all clean install:
	@ $(ECHO) "Doesn't build on this architecture: $(LLVMGOLD_TARGET_ARCH)"
endif

include $(ROOT)/llvm/Makefile.inc
