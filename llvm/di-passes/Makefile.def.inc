CFLAGS  += $(DYNINST_CFLAGS)
ifeq  ($(ARCH_NAME), x64)
	CFLAGS  += $(DYNINST_CFLAGS_X64)
else
	CFLAGS  += $(DYNINST_CFLAGS_X86)
endif
LDFLAGS += $(DYNINST_LDFLAGS) $(DYNINST_LIBS)

INCLUDES += -I../include
ifneq  ($(DYNINST_BUILD_INCS), no)
	INCLUDES += $(shell find $(DYNINST_ROOT) -maxdepth 2 -name h | awk '{ printf("-I%s ", $$1); }' )
	INCLUDES += $(shell find $(DYNINST_ROOT) -maxdepth 2 -name src | awk '{ printf("-I%s ", $$1); }' )
endif
