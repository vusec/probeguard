DIRS := sectionify bbclone debugify allocguard cfi dwarfer rdefender sfi

ROOT=../..
include $(ROOT)/Makefile.inc

LLVM_VERSION_GTE_31 = $(shell expr $(LLVM_VERSION) \>= 31)
LLVM_VERSION_GTE_33 = $(shell expr $(LLVM_VERSION) \>= 33)
LLVM_VERSION_GTE_34 = $(shell expr $(LLVM_VERSION) \>= 34)
LLVM_VERSION_GTE_37 = $(shell expr $(LLVM_VERSION) \>= 37)
ifeq ($(LLVM_VERSION_GTE_37),1)
EFFECTIVE_DIRS = $(DIRS)
else
LLVM37_ONLY = debugify
EFFECTIVE_DIRS = $(filter-out $(LLVM37_ONLY), $(DIRS))
endif

all: $(patsubst %,build_%,$(EFFECTIVE_DIRS))

$(patsubst %,build_%,$(DIRS)): DIR = $(subst build_,,$@)
$(patsubst %,build_%,$(DIRS)):
	@echo Building LLVM $(DIR)...
	$(MAKE) -C $(DIR) install

clean:
	$(foreach DIR, $(DIRS), $(MAKE) -C $(DIR) distclean;)

distclean: clean

install: all
