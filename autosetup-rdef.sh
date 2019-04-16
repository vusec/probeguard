#!/bin/bash

set -e

: ${PATHROOT:="$PWD"}
if [ ! -f "$PATHROOT/autosetup.inc" ]; then
	echo "Please execute from the root of the repository or set PATHROOT" >&2
	exit 1
fi

LLVMBRANCH=RELEASE_37/final
LLVMVERSION=3.7
LLVMVERSIONCONF=3.7

source "$PATHROOT/autosetup.inc"

# store settings
(
echo "export PATH=\"$PATHAUTOPREFIX/bin:\$PATH\""
echo "PATHTOOLS=\"$PATHAUTOPREFIX\""
echo "export PYTHONPATH=\"\$PYTHONPATH:${PATHAUTOPYTHON}\""
) > "$PATHROOT/apps/autosetup-paths.inc"

# build app
echo "Setting up ..."
cd "$PATHROOT/apps"
export JOBS
scripts/setup_rdef.sh "$PATHROOT" || (
	echo "ERROR: see $PATHROOT/rdef.setup.log for details" >&2
	exit 1
)

