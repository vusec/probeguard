###########################################################
# Main configuration (override in common.overrides.*inc to match your settings)
###########################################################
HAVE_LLVM=1
LLVMBASEDIR=/media/shared
LLVMPREFIX=${LLVMBASEDIR}/llvm-2.9/bin
LLVM_TWOSTEP_LINKING_WITH_GOLD=0
LLVM_TWOSTEP_LINKING_WITH_GOLD_USES_LLC=0
LLVM_OUTPUT_TRG_DIR=""
LLVM_CAP_ALL="CAP_AUDIT_CONTROL,CAP_AUDIT_WRITE,CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_DAC_READ_SEARCH,CAP_FOWNER,CAP_FSETID,CAP_IPC_LOCK,CAP_IPC_OWNER,CAP_KILL,CAP_LEASE,CAP_LINUX_IMMUTABLE,CAP_MAC_ADMIN,CAP_MAC_OVERRIDE,CAP_MKNOD,CAP_NET_ADMIN,CAP_NET_BIND_SERVICE,CAP_NET_BROADCAST,CAP_NET_RAW,CAP_SETGID,CAP_SETFCAP,CAP_SETPCAP,CAP_SETUID,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_CHROOT,CAP_SYS_MODULE,CAP_SYS_NICE,CAP_SYS_PACCT,CAP_SYS_PTRACE,CAP_SYS_RAWIO,CAP_SYS_RESOURCE,CAP_SYS_TIME,CAP_SYS_TTY_CONFIG,CAP_SYSLOG,CAP_SYS_MODULE"
###########################################################

###########################################################
# Common variables
###########################################################
ABS_ROOT=$(readlink -f ${ROOT}; true)

DUNE_DIR=${ABS_ROOT}/../dune
PERF_PATH=/usr/bin/perf
LLVMDIR=${ABS_ROOT}/llvm
LLVMINC=${LLVMDIR}/include
LLVMLIB=${LLVMDIR}/lib
INSTALL_DIR=${ABS_ROOT}/bin

LLVMSECTIONIFY_SO=${INSTALL_DIR}/sectionify.so
LLVMAOPIFY_SO=${INSTALL_DIR}/aopify.so
LLVMMAGIC_ST_IN_LIBST=0

CC=${LLVMPREFIX}/bin/clang
CXX=${LLVMPREFIX}/bin/clang++
CFLAGS="-fasynchronous-unwind-tables -g -I${LLVMINC}"
###########################################################

###########################################################
# LLVMDRV support (no longer in use by default)
###########################################################
LLVMDRV=${INSTALL_DIR}/llvmdrv
LLVMDRV_CC=${LLVMPREFIX}/bin/clang
LLVMDRV_STATIC_CC=${LLVMPREFIX}/bin/llvm-gcc
LLVMDRV_FLAGS="-llvm-prefix=${LLVMPREFIX}/bin -compiler=${LLVMDRV_CC} -uselinker=gcc -assembler=gcc -save-temps -Wllc-start -march=x86 -mattr=-sse2 -Wllc-end"
###########################################################

###########################################################
# LLVM gold plugin support (see README.llvm for details)
#
# Note: LLVMGOLD_PREFIX below should point to a valid LLVM 2.9 (+LLVMGOLD_CC=llvm-gcc) [or LLVM >= 3.0 (+LLVMGOLD_CC=clang)] installation with gold plugin support (binutils >=2.22)
###########################################################
LLVMGOLD_HAS_LTO_DISABLE_OPT=0
LLVMGOLD_PREFIX=${LLVMPREFIX}
LLVMGOLD_PLUGIN=${LLVMGOLD_PREFIX}/lib/LLVMgold.so

LLVMGOLD_CC="${LLVMGOLD_PREFIX}/bin/llvm-gcc -flto"
LLVMGOLD_CXX="${LLVMGOLD_PREFIX}/bin/llvm-g++ -flto"
LLVMGOLD_AR="ar --plugin ${LLVMGOLD_PLUGIN}"
LLVMGOLD_RANLIB="${LLVMGOLD_AR} -s"

LLVMGOLD_AR_FLAGS="--plugin ${LLVMGOLD_PLUGIN} -cru"
LLVMGOLD_CFLAGS="-fasynchronous-unwind-tables -g -pthread"
LLVMGOLD_LINK="-Wl,--plugin -Wl,${LLVMGOLD_PLUGIN}"
LLVMGOLD_LINKFLAGS="-Wl,-plugin-opt=-disable-fp-elim -Wl,-plugin-opt=-disable-inlining -Wl,-plugin-opt=also-emit-llvm"
LLVMGOLD_LINKCOMMONFLAGS="-rdynamic"
LLVMGOLD_LIBS="-pthread -lpthread -lgcc_s -lrt -ldl"
LLVMGOLD_LDFLAGS="${LLVMGOLD_LINK} ${LLVMGOLD_LINKFLAGS} ${LLVMGOLD_LINKCOMMONFLAGS} ${LLVMGOLD_LIBS}"
LLVMGOLD_OPTFLAGS="-disable-internalize -mem2reg -std-compile-opts"
LLVMGOLD_LLCFLAGS="--disable-fp-elim"
LLVMGOLD_TSLINK_PARTIALFLAGS="-Wl,-r -nostdlib"
LLVMGOLD_TSLINK_FINALFLAGS="-B${LLVMGOLD_PREFIX}/bfd_bin"
LLVMGOLD_OPTIMIZED=1

###########################################################

###########################################################
# DynInst support
###########################################################
HAVE_DYNINST=0
DYNINST_ROOT=${ABS_ROOT}/../dyninst
DYNINST_LIB_DIR=${DYNINST_ROOT}/install/lib
DYNINST_RT_LIB=${DYNINST_LIB_DIR}/libdyninstAPI_RT.so
DYNINST_CFLAGS="-D__STDC_LIMIT_MACROS -Wno-deprecated -Dos_linux -I${DYNINST_ROOT}"
DYNINST_CFLAGS_X86="-Darch_x86 -Di386_unknown_linux2_0 -DARCH=x86"
DYNINST_CFLAGS_X64="-Darch_x86_64 -Dx86_64_unknown_linux2_4 -DARCH=x64"
DYNINST_LDFLAGS="-L${DYNINST_LIB_DIR}"
DYNINST_LIBS="-lcommon -ldyninstAPI -linstructionAPI -lparseAPI -lpatchAPI -lsymtabAPI"
###########################################################

###########################################################
# Dynamorio support
###########################################################
HAVE_DYNAMORIO=0
DYNAMORIO_HOME=${ABS_ROOT}/../dynamorio
###########################################################

###########################################################
# PIN support
###########################################################
HAVE_PIN=0
PIN_ROOT=${ABS_ROOT}/../pin
###########################################################
