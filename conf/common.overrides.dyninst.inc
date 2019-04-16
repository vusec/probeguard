DYNINST_ROOT=${ABS_ROOT}/autosetup.dir/dyninst
HAVE_DYNINST=1
DYNINST_CFLAGS+=" -I${DYNINST_ROOT}/install/include -I${ABS_ROOT}/autosetup.dir/install/include"
CFLAGS+=" -fPIC"
LDFLAGS+=" -fPIC"
