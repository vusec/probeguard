#!/bin/bash

set -e

# This script compiles a number of important packages and installs them
# in the autosetup.dir/install directory to avoid problems with bad versions
# or packages that have been broken by the distribution.
# However, a number of packages needs to be installed beforehand.
# The script has been tested on a clean Ubuntu 14.04.4 LTS Server system
# with the following packages installed:
#
# sudo apt-get install bison flex g++ gcc gcc-multilib gettext git \
#                      libboost-dev libboost-system-dev libboost-thread-dev \
#                      make pkg-config ssh subversion texlive zlib1g-dev

# incoming variables expected:
# - LLVMBRANCH
# - LLVMVERSION
# - LLVMVERSIONCONF
# - PATHROOT

corecount="`grep '^processor' /proc/cpuinfo|wc -l`"

: ${CLEAN=0}
: ${JOBS="`expr "$corecount" "*" 2`"}

: ${PATHAUTOSETUP="$PATHROOT/autosetup.dir"}
: ${PATHAUTOPKGS="$PATHROOT/autosetup/packages"}
: ${PATHAUTOPREFIX="$PATHAUTOSETUP/install"}
: ${PATHAUTOSRC="$PATHAUTOSETUP/src"}
: ${PATHAUTOPYTHON=""}
: ${PATHAUTOSTATE="$PATHAUTOSETUP/state"}
: ${PATHDYNINST:="$PATHAUTOSETUP/dyninst"}
: ${PATHLLVM:="$PATHAUTOSRC/`uname -m`"}
: ${PATHLOG="$PATHROOT/autosetup-log.txt"}
: ${PATHVMS:="$PATHAUTOSETUP/vms"}

: ${VERSIONBASH=bash-4.3}
: ${VERSIONBINUTILS=binutils-2.27}
: ${VERSIONCMAKE=cmake-3.5.1}
: ${VERSIONCMAKEURL=v3.5}
: ${VERSIONCOREUTILS=coreutils-8.22}
: ${VERSIONDYNINST=DyninstAPI-9.0.3}
: ${VERSIONDYNINSTURL=release9.0.3}
: ${VERSIONGLIB=glib-2.44.1}
: ${VERSIONGLIBURL=2.44}
: ${VERSIONLIBELF=libelf-0.8.13}
: ${VERSIONLIBFFI=libffi-3.2.1}
: ${VERSIONLIBIBERTY=binutils-2.25}
: ${VERSIONPIXMAN=pixman-0.32.6}
: ${VERSIONKOMBIT=1.0a4}

PATHBINUTILS="$PATHAUTOSRC/$VERSIONBINUTILS"
MYPWD=`pwd`

usage()
(
	echo "$@" >&2

	echo "usage:"
	echo "  autosetup-linux.sh"
	echo "  autosetup-minix.sh"
	echo ""
	echo "relevant environment variables:"
	echo "- CLEAN can be set to 1 to start with a clean slate"
	echo "- JOBS can be set to the number of concurrent processes make can use"
	echo "- PATHROOT can be set to the root of the repository (default: cwd)"
	exit 1
)

[ -f "$PATHROOT/autosetup.inc" ] || usage "ERROR: PATHROOT is incorrect"
[ "$LLVMBRANCH" != "" ] || usage "ERROR: LLVMBRANCH is not set"
[ "$LLVMVERSION" != "" ]|| usage "ERROR: LLVMVERSION is not set"
[ "$LLVMVERSIONCONF" != "" ]|| usage "ERROR: LLVMVERSIONCONF is not set"
[ "$#" -eq 0 ] || usage "ERROR: invalid number of arguments"

if [ "$CLEAN" -ne 0 ]; then
	echo "Cleaning up old state"
	rm -rf "$PATHAUTOSETUP"
fi

export PATH="$PATHAUTOPREFIX/bin:$PATH"

exec 5> "$PATHLOG"

run()
{
	echo -------------------------------------------------------------------------------- >&5
	echo "command:          $*"               >&5
	echo "\$PATH:            $PATH"            >&5
	echo "working dir:      $PWD"             >&5
	echo -------------------------------------------------------------------------------- >&5
	if "$@" >&5 2>&5; then
		echo "[done]" >&5
	else
		echo "Command '$*' failed in directory $PWD with exit code $?, please check $PATHLOG for details" >&2
		exit 1
	fi
}

echo "Creating directories"
run mkdir -p "$PATHAUTOSRC"
run mkdir -p "$PATHAUTOSTATE"

# build bash to override the system's default shell
statefile="$PATHAUTOSTATE/bash"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/bash.inc
fi

# build a sane version of coreutils
statefile="$PATHAUTOSTATE/coreutils"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/coreutils.inc
fi

# build binutils to ensure we have gold
statefile="$PATHAUTOSTATE/binutils"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/binutils.inc
fi

# build cmake
statefile="$PATHAUTOSTATE/cmake"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/cmake.inc
fi

# build libelf, needed by libdwarf
statefile="$PATHAUTOSTATE/libelf"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/libelf.inc
fi

# build libdwarf, shared library build needed by dyninst
statefile="$PATHAUTOSTATE/libdwarf"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/libdwarf.inc
fi

# build libiberty, PIC build needed by dyninst
statefile="$PATHAUTOSTATE/libiberty"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/libiberty.inc
fi

# build dyninst
statefile="$PATHAUTOSTATE/dyninst"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/dyninst.inc
fi

# build LLVM
cd $MYPWD
statefile="$PATHAUTOSTATE/llvm"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/llvm.inc
fi

# configure llvm-apps
statefile="$PATHAUTOSTATE/llvm-apps-configure-$LLVMVERSIONCONF"
if [ ! -f "$statefile" ]; then
	echo "Configuring llvm-apps"
	cd "$PATHROOT"
	run rm -f "$PATHAUTOSTATE"/llvm-apps-configure-* || true
	run cp conf/common.overrides.conf.inc common.overrides.local.inc || true
	clean="y" install_pkgs="n" have_llvm="y" have_di="y" di_root="$PATHDYNINST" have_dr="n" llvm_version="$LLVMVERSIONCONF" llvm_basedir="$PATHLLVM" have_pin="n" have_dune="n" minix_conf="n" ov_PIE="n" ov_dsa="n" ov_gdb="y" ov_segfault="n" ./configure
	touch "$statefile"
        echo "        done."
fi

# Setup kombit (to help define execution variations)
statefile="$PATHAUTOSTATE/kombit-installation"
if [ ! -f "$statefile" ]; then
	source "$PATHAUTOPKGS"/kombit.inc
fi
