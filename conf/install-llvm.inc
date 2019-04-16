# Root directory for compilation and installation of LLVM binaries
: ${PATHAUTOSRC=$HOME/llvmbin}
: ${LLVMBIN_ROOT=$PATHAUTOSRC}
: ${PATH_TO_LLVM_APPS=`pwd`}

# Set the LLVM version that is to be installed.
: ${LLVM_VERSION=4.0}

# The install directory for LLVM binaries
LLVMPREFIX="${LLVMBIN_ROOT}/`uname -m`/llvm-${LLVM_VERSION}/bin"

# Path to llvm-apps repository
PATH_TO_LLVM_APPS="$PATHROOT"

# Binutils tar ball file name
BINUTILS_NAME="binutils-2.27.90"

# Binutils path
BINUTILS_PATH="$LLVMBIN_ROOT/`uname -m`/binutils"

# Control to switch ON/OFF execution stages of install-llvm.sh script
INSTALL_BINUTILS=1
FORCE_INSTALL_BINUTILS=0
FETCH_LLVM=1
FETCH_CLANG=1
FETCH_ASAN=0
INSTALL_LLVM=1
INSTALL_CLANG=1
INSTALL_ASAN=0
FETCH_DSA=0
INSTALL_DSA=0
