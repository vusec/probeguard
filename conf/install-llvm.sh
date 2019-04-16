#!/bin/bash

########################################
# Author: Koustubha Bhat
# Date : 29-Apr-2015

# 22-Feb-2016 : Generalizing the script
# 10-Mar-2017 : Updating for LLVM 4.0 (Dmitrii Kuvaiskii)
#######################################

LLVM_34_POOLALLOC_COMMIT="85eae01c5064c5d6d61378deb08a4c155256695c"
LLVM_37_POOLALLOC_COMMIT="eb3a28cc226248240eb05273f543aca074979930"
LOGFILE="`pwd`/llvm-install.log"
: ${RELEASE=34}
: ${NUM_JOBS=8}
: ${SETTINGS_INC_FILE=./install-llvm.inc}

set -e

if [ ! -f ${SETTINGS_INC_FILE} ]; then
	echo "File not found : settings-llvm.conf."
	exit 2
fi
. ${SETTINGS_INC_FILE}

BINUTILS_TARBALL="${BINUTILS_NAME}.tar.bz2"

# Install directories
BIN_DIR=${LLVMPREFIX}
DEBUG_BIN_DIR=${LLVMPREFIX}/../debug_bin

# Build directories
OBJ_DIR_HOME=${LLVMPREFIX}/../llvm-objects
OBJ_DIR_LLVM=${LLVMPREFIX}/../llvm-objects/llvm
OBJ_DIR_CLANG=${LLVMPREFIX}/../llvm-objects/llvm/tools/clang
OBJ_DIR_ASAN=${LLVMPREFIX}/../llvm-objects/llvm/projects/compiler-rt

# Source directories
SRC_DIR_HOME=${LLVMPREFIX}/..
SRC_DIR_LLVM=${SRC_DIR_HOME}/llvm
SRC_DIR_CLANG=${SRC_DIR_LLVM}/tools/clang
SRC_DIR_ASAN=${SRC_DIR_LLVM}/projects/compiler-rt

# ----------------------------------------------------------------------------------------------
# COMMON FUNCTIONS
# ----------------------------------------------------------------------------------------------
#Pre-req steps on Ubuntu 12.04
linux_prereqs()
{
if [ ! -f "./.prereq-done" ]; then
sudo apt-get -y install build-essential apt-utils dialog sudo vim wget subversion mc python python-dev cython libssl1.0.0 libssl-dev libncurses5-dev psmisc gdb strace ltrace ftp ssh time netcat automake sendemail
sudo apt-get -y install libstdc++6-4.4-dev libdb-dev libX11-dev libxt-dev libxaw7
sudo apt-get -y build-dep uuid-dev libpq-dev llvm-3.4

set -x
_L=/lib/libcrypt.so; _F=/lib/i386-linux-gnu/libcrypt.so.1; if [ ! -L $_L ]; then sudo ln -s $_F $_L; fi
_L=/lib/libcrypto.so; _F=/lib/i386-linux-gnu/libcrypto.so.1.0.0; if [ ! -L $_L ]; then sudo ln -s $_F $_L; fi
_F=/lib/i386-linux-gnu/libm.so.6; _L=/lib/libm.so.6; if [ ! -L $_L ]; then sudo ln -s $_F $_L; fi
_F=/lib/i386-linux-gnu/libcap.so; _L=/lib/libcap.so; if [ ! -L $_L ]; then sudo ln -s $_F $_L; fi
_F=/lib/i386-linux-gnu/libpam.so.0; _L=/lib/libpam.so.0; if [ ! -L $_L ]; then sudo ln -s $_F $_L; fi
touch "./.prereq-done"
fi
}

init()
{
	# Dmitrii Kuvaiskii: installing pre-req is left for old versions of LLVM
	if [ "${LLVM_VERSION}" == "3.4" ] ;
	then
		linux_prereqs
	fi

	if [ ! -d ${PATH_TO_LLVM_APPS} ]; then
		echo "llvm-repository directory not found"
		exit 2
	fi

	if [ ! -d ${LLVMPREFIX} ]; then
		mkdir -p ${LLVMPREFIX}
	fi

	# Select release
	case ${LLVM_VERSION} in
			"3.4")	RELEASE=34
							OBJ_DIR_LLVM=${OBJ_DIR_HOME}
							OBJ_DIR_CLANG=${OBJ_DIR_HOME}/tools/clang			# Will not be used.
							OBJ_DIR_ASAN=${OBJ_DIR_HOME}/projects/compiler-rt

					;;
			"3.7")	RELEASE=37
					;;
			"4.0")	RELEASE=40
					;;
				*)
					RELEASE=34
					;;
	esac
}

cmake_install()
{
  SRCDIR=$1
  BUILDDIR=$2
	CMAKE_ADDL_OPTIONS=$3
  INSTALLDIR=${BIN_DIR}

  echo "Build dir: $BUILDDIR"
  echo "Install dir: ${INSTALLDIR}"
  cd $BUILDDIR
  cmake ${CMAKE_ADDL_OPTIONS} $SRCDIR
  cmake -DCMAKE_INSTALL_PREFIX:PATH=${INSTALLDIR} -DLLVM_ENABLE_ASSERTIONS:BOOL=ON -DCMAKE_BUILD_TYPE:STRING=Release ${CMAKE_ADDL_OPTIONS} ${BUILDDIR}
  make -j${NUM_JOBS}
  make install
}

# ----------------------------------------------------------------------------------------------
# FETCH FROM REPOSITORIES
# ----------------------------------------------------------------------------------------------

get_llvm()
{
	RELEASE=$1

 cd ${SRC_DIR_HOME}
 pwd
 echo "Fetching LLVM ..."
 git clone git@github.com:llvm-mirror/llvm.git
 cd llvm
 git checkout release_$1
 if [ $? -eq 1 ]; then
  	echo "Error in checking out branch: release_$RELEASE"
	  exit 1
 fi
}

get_clang()
{
 RELEASE=$1

# Fetch llvm from the sources
 cd ${SRC_DIR_HOME}/llvm/tools
 echo "Fetching Clang..."
 if [ -d clang ]; then rm -rf clang; fi
 git clone git@github.com:llvm-mirror/clang.git
 cd clang
 git checkout release_$RELEASE
 if [ $? -eq 1 ]; then
        echo "Error in checking out branch: release_$RELEASE"
          exit 1
 fi
}

get_asan()
{
	release=$1
  echo "Fetching compiler-rt..."
  if [ -d ${SRC_DIR_ASAN} ]; then rm -rf ${SRC_DIR_ASAN}; fi
  # (cd ${LLVMPREFIX}/../llvm/projects && git clone https://github.com/llvm-mirror/compiler-rt.git && git reset --hard 4b51ed46e4e1cc2e19b8fff72f4458a01bfa6ac2)
	(cd ${SRC_DIR_LLVM}/projects && git clone https://github.com/llvm-mirror/compiler-rt.git )
	(cd ${SRC_DIR_ASAN} && git checkout release_$release)
}

# DSA poolalloc installation is through autoconfig
# Doesn't work with cmake
get_dsa()
{
	release=$1
	cd ${SRC_DIR_LLVM}
# **** Rather let me get poolalloc from this git repository: (for DSA)
 echo "Fetching poolalloc ..."
 (cd projects && git clone https://github.com/llvm-mirror/poolalloc.git)

 # Apply applicable patch
	if [ "$release" == "34" ]; then
		(cd projects/poolalloc && git reset --hard ${LLVM_34_POOLALLOC_COMMIT} )
	else
		(cd projects/poolalloc && git reset --hard ${LLVM_37_POOLALLOC_COMMIT} )
	fi
	if [ -e ${PATH_TO_LLVM_APPS}/conf/poolalloc-patches/llvm${LLVM_VERSION}.patch ]; then
       		(cd projects/poolalloc && git apply ${PATH_TO_LLVM_APPS}/conf/poolalloc-patches/llvm${LLVM_VERSION}.patch)
	fi
echo "			[done]"
echo
}

# ----------------------------------------------------------------------------------------------
# INSTALL FUNCTIONS
# ----------------------------------------------------------------------------------------------

install_binutils()
{
# *** Download and extract
if [ ! -d ${BINUTILS_PATH} ]; then
	mkdir -p ${BINUTILS_PATH}
fi
# Skip if already installed.
if [ "${FORCE_INSTALL_BINUTILS}" == "0" ] \
&& [ -e ${BINUTILS_PATH}/bin/include/plugin-api.h ] \
&& [ -e ${BINUTILS_PATH}/bin/lib/libbfd.so ] \
&& [ -e ${BINUTILS_PATH}/bin/lib/libopcodes.so ]; then 
	echo -n "${BINUTILS_NAME} already found here: ${BINUTILS_PATH}/bin"
	echo "	[ Skipping ahead ]"
	return 
fi

# *** Install binutils with gold support
if [ "${INSTALL_BINUTILS}" != "0" ]; then
	echo "Installing binutils (${BINUTILS_NAME})... "
	cd ${BINUTILS_PATH}
	if [ ! -e ${BINUTILS_TARBALL} ]; then
	wget ftp://sourceware.org/pub/binutils/snapshots/${BINUTILS_TARBALL} #to ${LLVMPREFIX}/../binutils #(${LLVMPREFIX} is /path/to/llvm/bin)
	fi
	if [ ! -d ${BINUTILS_NAME} ]; then tar -xf ${BINUTILS_TARBALL}; fi
	cd ${BINUTILS_NAME}
	if [ ! -d ${BINUTILS_PATH}/bin ]; then
		mkdir -p ${BINUTILS_PATH}/bin
	fi
	./configure --prefix=${BINUTILS_PATH}/bin --enable-shared --enable-gold --enable-plugins --disable-werror
	make all-gold
	make install || true
	if [ ! -e ${BINUTILS_PATH}/bin/include/plugin-api.h ] || [ ! -e ${BINUTILS_PATH}/bin/lib/libbfd.so ] || [ ! -e ${BINUTILS_PATH}/bin/lib/libopcodes.so ]; then 
	  echo "Failure during installation of binutils."
	  exit 1
	fi
	echo "			[done]"
	echo
fi
}

install_llvm()
{
	release=$1

	# Ensure build and install directories are sane
	if [ -e ${BIN_DIR} ]; then
		read -p "Are you sure you want to delete: $BIN_DIR ? [y|n]" confirm
		if [ "y" != "$confirm" ];
		then
			rm -rf ${BIN_DIR} ${DEBUG_BIN_DIR} ${OBJ_DIR_HOME} 2>/dev/null || true
		fi
	fi
	if [ ! -d ${BIN_DIR} ]; then  mkdir ${BIN_DIR} ; fi
        if [ ! -d ${DEBUG_BIN_DIR} ]; then  mkdir ${DEBUG_BIN_DIR}; fi
	if [ ! -d ${OBJ_DIR_LLVM} ]; then  mkdir -p $OBJ_DIR_LLVM; fi
	if [ ! -d ${OBJ_DIR_CLANG} ]; then  mkdir -p $OBJ_DIR_CLANG; fi
	if [ ! -d ${OBJ_DIR_ASAN} ]; then  mkdir -p ${OBJ_DIR_ASAN}; fi
	
	cd ${OBJ_DIR_HOME}

	case $release in
				"34")
						 echo "Building and installing LLVM ..."
						 ../llvm/configure --prefix=${BIN_DIR} --enable-bindings=none --disable-debug-symbols --enable-optimized --enable-assertions --enable-jit --with-binutils-include=${BINUTILS_PATH}/${BINUTILS_NAME}/include
						 BUILD_CLANG_ONLY=YES make
						 make install
						 ;;

			 "34_debug")
						../llvm/configure --prefix=${DEBUG_BIN_DIR} --enable-bindings=none --disable-optimized --enable-debug-runtime --enable-assertions --enable-jit --with-binutils-include=${BINUTILS_PATH}/${BINUTILS_NAME}/include
						BUILD_CLANG_ONLY=YES make
						make install
						;;

				"37")
					cmake_install ${SRC_DIR_LLVM} ${OBJ_DIR_LLVM} "-DLLVM_CONFIG:PATH=${OBJ_DIR_LLVM}/bin/llvm-config -DLLVM_BINUTILS_INCDIR=${BINUTILS_PATH}/${BINUTILS_NAME}/include -DLLVM_ENABLE_LTO:STRING=Full"
						;;

				"40")
					cmake_install ${SRC_DIR_LLVM} ${OBJ_DIR_LLVM} "-DLLVM_CONFIG:PATH=${OBJ_DIR_LLVM}/bin/llvm-config -DLLVM_BINUTILS_INCDIR=${BINUTILS_PATH}/${BINUTILS_NAME}/include"
						;;

					*)
						echo "Invalid llvm release version selected."
						;;
	esac

	mkdir -p ${BIN_DIR}/bfd_bin; ln -f -s `readlink -f /usr/bin/ld.bfd` ${BIN_DIR}/bfd_bin/ld #required to support two-step linking

 cd ${LLVMPREFIX}/..

echo "			[done]"
echo
}

install_clang()
{
	if [ ! -d ${OBJ_DIR_CLANG} ]; then mkdir -p ${OBJ_DIR_CLANG}; fi
	cmake_install ${SRC_DIR_CLANG} ${OBJ_DIR_CLANG} -DLLVM_CONFIG:PATH=${OBJ_DIR_LLVM}/bin/llvm-config
}

install_dsa()
{
 release=$1
 echo "Building and installing DSA..."
 cd ${OBJ_DIR_LLVM}
 #if [ "$release" == "34" ]; then
	 echo "../../llvm/configure --prefix=${BIN_DIR} --enable-bindings=none --disable-debug-symbols --enable-optimized --enable-assertions --enable-jit --with-binutils-include=${BINUTILS_PATH}/${BINUTILS_NAME}/include"
	 ${SRC_DIR_LLVM}/configure --prefix=${BIN_DIR} --enable-bindings=none --disable-debug-symbols --enable-optimized --enable-assertions --enable-jit --with-binutils-include=${BINUTILS_PATH}/${BINUTILS_NAME}/include --with-llvmsrc=${SRC_DIR_LLVM} --with-llvmobj=${OBJ_DIR_LLVM}
	 cd projects/poolalloc
	 make -j8
	 make install
 echo "			[done]"
 echo
}

main()
{
	set -e
	init
	echo "LLVM version to be installed: ${LLVM_VERSION}"
	echo "LLVM release selected 			:	${RELEASE}"
	echo "LLVMPREFIX specified	  : ${LLVMPREFIX}"
	echo "Platform 			  : `uname -m`"

	if [ "${INSTALL_BINUTILS}" != "0" ]; then
		install_binutils
	fi

	if [ "${FETCH_LLVM}" != "0" ]; then
		get_llvm $RELEASE
	fi

	if [ "${FETCH_CLANG}" != "0" ]; then
		get_clang $RELEASE
	fi

	if [ "${FETCH_ASAN}" != "0" ]; then
		get_asan $RELEASE
	fi

	if [ "${INSTALL_LLVM}" != "0" ]; then
		install_llvm $RELEASE
	else
		local make_llvm=0
		if [ "$INSTALL_CLANG" != "0" ]; then
			install_clang $RELEASE
			make_llvm=1
		fi
		if [ "${INSTALL_ASAN}" != "0" ]; then
			install_llvm $RELEASE
			make_llvm=1
		fi
		if [ $make_llvm -eq 1 ]; then
			cd ${OBJ_DIR_LLVM}
			make -j${NUM_JOBS}
			make install
		fi
	fi

	# Keep DSA for the final leg. After this we would have a mix of
	# autoconf and cmake files.

	if [ "${FETCH_DSA}" != "0" ]; then
		get_dsa $RELEASE
	fi

	if [ "${INSTALL_DSA}" != "0" ]; then
		install_dsa $RELEASE
	fi
}

main $@  | tee -a $LOGFILE
