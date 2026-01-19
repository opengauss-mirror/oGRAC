set -e
echo "compile unixODBC"
export WORKSPACE=$(dirname $(dirname $(pwd)))
export LIBRARY=${WORKSPACE}/oGRAC/library/
export BUILD_DEPENDENCE=${WORKSPACE}/oGRAC/build_dependence/

cd ${BUILD_DEPENDENCE}/unixODBC
echo "cd unixODBC"
cd libltdl/
autoreconf; chmod 755 configure; CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC --param ssp-buffer-size=4 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' ./configure
cd ../; autoreconf
CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC --param ssp-buffer-size=4 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' ./configure --prefix=${BUILD_DEPENDENCE}/unixODBC
cp ${BUILD_DEPENDENCE}/unixODBC/*.h ${BUILD_DEPENDENCE}/unixODBC/include
