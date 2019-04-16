LLVMPREFIX=${LLVMBASEDIR}/llvm-3.7/bin
LLVMGOLD_LINK=""
LLVMGOLD_CC="${LLVMGOLD_PREFIX}/bin/clang -flto"
LLVMGOLD_CXX="${LLVMGOLD_PREFIX}/bin/clang++ -flto"
LLVMGOLD_LINKFLAGS="-Wl,-plugin-opt=-disable-fp-elim -Wl,-plugin-opt=save-temps"
LLVMGOLD_HAS_LTO_DISABLE_OPT=0
LLVMGOLD_OPTFLAGS="-std-link-opts -mem2reg "
CFLAGS+="-DLLVM_HAS_MPX=0" 
