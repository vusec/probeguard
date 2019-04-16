ROOT=../../..

include $(ROOT)/Makefile.inc

MODULE = random.bcc
SRCS = random.c 

SECTION_NAME=rdefender_functions

CFLAGS += $(CXXFLAGS) -pedantic -std=gnu99 -Wall -g -Wno-long-long -D_GNU_SOURCE -DLOGGING 

LOPT_FLAGS = -load=$(LLVMSECTIONIFY_SO) -sectionify -sectionify-no-override -sectionify-data-section-map=.*/random_data -sectionify-function-section-map=.*/$(SECTION_NAME)

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
