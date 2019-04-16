ROOT=../../..

include $(ROOT)/Makefile.inc

MODULE = sfi.bcc
SRCS = sfi.c aes.c mpx.c

SECTION_NAME=rdefender_functions

INCLUDES = -I../../include/sfi

ifeq ($(RDEF_SFI),1)			# SFI_MASK is set already by default in ../../include/sfi/sfi.h
CFLAGS+=-DSFI_MASK="0x7FFFFFFFFFFFL"	# 47 bits set. For attack prevention we must here reduce the mask to 47 bits
endif


CFLAGS += $(CXXFLAGS) -pedantic -std=gnu99 -Wall -g -Wno-long-long -D_GNU_SOURCE -mavx -maes

LOPT_FLAGS = -load=$(LLVMSECTIONIFY_SO) -sectionify -sectionify-no-override -sectionify-data-section-map=.*/sfi_data -sectionify-function-section-map=.*/$(SECTION_NAME)

$(MODULE): $(SRCS)
	$(LLVMGOLD_CC) $(CFLAGS) $(LLVMGOLD_CFLAGS) $(LLVMGOLD_LDFLAGS) $(INCLUDES) -shared -o $@.o $(SRCS)
	$(LLVMPREFIX)/bin/opt $(LOPT_FLAGS) -o $@ $@.o.bc

all: $(MODULE)

install: $(INSTALL_DIR)/$(MODULE)

$(INSTALL_DIR)/$(MODULE): $(MODULE)
	install -c -D -m 744 $? $@

clean:
	rm -f *.BCC *.bcc *.bc *.BCL *.BCL.sh *.bcl *.o *.s

distclean: clean
