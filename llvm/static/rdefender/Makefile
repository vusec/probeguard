ROOT=../../..

include $(ROOT)/Makefile.inc

ifeq ($(FOR_SPEC),1)
CFLAGS+=-DFOR_SPEC
endif
ifeq ($(RDEF_HARDEN_ONE_FUNC),1)
CFLAGS+=-DRDEF_HARDEN_ONE_FUNC
endif

MODULE = rdefender.bcc
SRCS =	rdefender.c \
	rdef_net.c	\
	rdiag.c		\
	rdef_signal.c	\
	rdef_react.c	\
	rdef_test.c

CFLAGS += $(CXXFLAGS) -pedantic -std=gnu99 -Wall -g -Wno-long-long -D_GNU_SOURCE -DRDEF_LOG_TO_FILE

LOPT_FLAGS = -load=$(LLVMSECTIONIFY_SO) -sectionify -sectionify-no-override -sectionify-data-section-map=.*/rdefender_data -sectionify-function-section-map=.*/rdefender_functions

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
