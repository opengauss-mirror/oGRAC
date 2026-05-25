#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e

declare BEP

export WORKSPACE=$(dirname $(dirname $(pwd)))
export OPEN_SOURCE=${WORKSPACE}/ogracKernel/open_source
export LIBRARY=${WORKSPACE}/ogracKernel/library
export PLATFORM=${WORKSPACE}/ogracKernel/platform
export OS_ARCH=$(uname -i)
DFT_WORKSPACE="/home/regress"
export TP_PREFIX="${OPEN_SOURCE}/local"
mkdir -p "${TP_PREFIX}"
export PATH="${TP_PREFIX}/bin:${PATH}"
export LD_LIBRARY_PATH="${TP_PREFIX}/lib:${TP_PREFIX}/lib64:${LD_LIBRARY_PATH:-}"
export CPPFLAGS="-I${TP_PREFIX}/include ${CPPFLAGS:-}"
export LDFLAGS="-L${TP_PREFIX}/lib -L${TP_PREFIX}/lib64 ${LDFLAGS:-}"
export CMAKE_PREFIX_PATH="${TP_PREFIX}:${CMAKE_PREFIX_PATH:-}"

apply_spec_patches_to_dir() {
  # Assume target_dir is an already-extracted source tree; spec and patches are in its parent directory.
  # Only apply patches listed in the spec; do not handle extraction here.
  local target_dir="$1"
  cd "${target_dir}"

  local parent_dir spec_file
  parent_dir="$(cd .. && pwd)"

  spec_file=$(cd "${parent_dir}" && ls *.spec | head -n1)

  # Apply patches in the order defined in the spec (PatchN:) from the parent directory
  ( cd "${parent_dir}" && grep -E '^Patch[0-9]+:' "${spec_file}" | awk '{print $2}' ) | while read -r p; do
    [ -n "${p}" ] || continue
    patch -p1 < "${parent_dir}/${p}" >/dev/null 2>&1
  done
}

echo $DFT_WORKSPACE " " $WORKSPACE
if [[ "$WORKSPACE" == *"regress"* ]]; then
    echo $DFT_WORKSPACE " eq " $WORKSPACE
else
    CURRENT_PATH=$(dirname $(readlink -f $0))
    CODE_PATH=$(cd "${CURRENT_PATH}/.."; pwd)
    export OPEN_SOURCE=${CODE_PATH}/open_source
    export LIBRARY=${CODE_PATH}/library
    export PLATFORM=${CODE_PATH}/platform
fi

# pcre (openEuler pcre2 spec layout)
cd ${OPEN_SOURCE}
rm -rf pcre
mv pcre2 pcre
cd ${OPEN_SOURCE}/pcre
rm -rf pcre2-10.42
tar -xjf pcre2-10.42.tar.bz2
# Use spec + patches to generate patched source tree
apply_spec_patches_to_dir "${OPEN_SOURCE}/pcre/pcre2-10.42"
cd ${OPEN_SOURCE}/pcre/pcre2-10.42
touch configure.ac aclocal.m4 Makefile.in configure config.h.in
mkdir -p pcre-build; chmod 755 -R ./*
aclocal; autoconf; autoreconf -vif
# 判断系统是否是centos，并且参数bep是否为true，都是则删除。
if [[ ! -z ${BEP} ]]; then
    if [[ -n "$(cat /etc/os-release | grep CentOS)" ]] && [[ ${BEP} == "true" ]] && [[ "${BUILD_TYPE}" == "RELEASE" ]]; then
        sed -i "2653,2692d" configure  # 从2653到2692行是构建环境检查，检查系统时间的。做bep固定时间戳时，若是centos系统，系统时间固定，必须删除构建环境检查，才能编译，才能保证两次出包bep一致；若是euler系统，可不用删除，删除了也不影响编译。
    fi
fi

./configure --prefix="${TP_PREFIX}" --libdir="${TP_PREFIX}/lib"
CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' ./configure --enable-utf8 --enable-unicode-properties --prefix=${OPEN_SOURCE}/pcre/pcre2-10.42/pcre-build --disable-stack-for-recursion
make; make check; make install
cd .libs/; tar -cvf libpcre.tar libpcre2-8.so*; mkdir -p ${LIBRARY}/pcre/lib/; cp libpcre.tar libpcre2-8.so* ${LIBRARY}/pcre/lib/
mkdir -p ${OPEN_SOURCE}/pcre/include/
cp ${OPEN_SOURCE}/pcre/pcre2-10.42/src/pcre2.h ${OPEN_SOURCE}/pcre/include/

# zstd (build from openGauss-third_party zstd component)
rm -rf ${OPEN_SOURCE}/openGauss-third_party/output/kernel/dependency/zstd || true
cd ${OPEN_SOURCE}/openGauss-third_party/dependency/zstd
sh build.sh
mkdir -p ${OPEN_SOURCE}/Zstandard/include
mkdir -p ${LIBRARY}/Zstandard/lib
cp ${OPEN_SOURCE}/openGauss-third_party/output/kernel/dependency/zstd/include/zstd.h ${OPEN_SOURCE}/Zstandard/include
cd ${OPEN_SOURCE}/openGauss-third_party/output/kernel/dependency/zstd/lib
rm -f libzstd.so libzstd.so.1
ln -s libzstd.so.1.5.6 libzstd.so
ln -s libzstd.so.1.5.6 libzstd.so.1
tar -cvf libzstd.tar libzstd.so*
cp libzstd.tar libzstd.so* ${LIBRARY}/Zstandard/lib/
mkdir -p ${LIBRARY}/Zstandard/bin
cp ${OPEN_SOURCE}/openGauss-third_party/output/kernel/dependency/zstd/bin/zstd ${LIBRARY}/Zstandard/bin/

# protobuf (openEuler protobuf spec layout)
cd ${OPEN_SOURCE}/protobuf
rm -rf protobuf-3.14.0
tar -xzf protobuf-all-3.14.0.tar.gz
apply_spec_patches_to_dir "${OPEN_SOURCE}/protobuf/protobuf-3.14.0"
cd ${OPEN_SOURCE}/protobuf/protobuf-3.14.0
./autogen.sh
# BEP pipeline option
if [[ ! -z ${BEP} ]]; then
    if [[ -n "$(cat /etc/os-release | grep CentOS)" ]] && [[ ${BEP} == "true" ]] && [[ "${BUILD_TYPE}" == "RELEASE" ]];then
        sed -i "2915,2949d" configure
    fi
fi
./configure --prefix="${TP_PREFIX}" --libdir="${TP_PREFIX}/lib"
if [[ ${OS_ARCH} =~ "x86_64" ]]; then
    export CPU_CORES_NUM_x86=`cat /proc/cpuinfo |grep "cores" |wc -l`
    make -j${CPU_CORES_NUM_x86}
elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
    export CPU_CORES_NUM_arm=`cat /proc/cpuinfo |grep "architecture" |wc -l`
    make -j${CPU_CORES_NUM_arm}
else 
    echo "OS_ARCH: ${OS_ARCH} is unknown, set CPU_CORES_NUM=16 "
    export CPU_CORES_NUM=16
    make -j${CPU_CORES_NUM}
fi
make install

# protobuf-c (openEuler protobuf-c spec layout)
cd ${OPEN_SOURCE}/protobuf-c
rm -rf protobuf-c-1.4.1
tar -xzf v1.4.1.tar.gz
apply_spec_patches_to_dir "${OPEN_SOURCE}/protobuf-c/protobuf-c-1.4.1"
cd ${OPEN_SOURCE}/protobuf-c/protobuf-c-1.4.1
# set pkg-config path
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
export PKG_CONFIG_PATH="${TP_PREFIX}/lib/pkgconfig:${TP_PREFIX}/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
# BEP pipeline option
if [[ ! -z ${BEP} ]]; then
    if [[ -n "$(cat /etc/os-release | grep CentOS)" ]] && [[ ${BEP} == "true" ]] && [[ "${BUILD_TYPE}" == "RELEASE" ]];then
        sed -i "2692,2726d" configure
    fi
fi
autoreconf -vif
./configure --prefix="${TP_PREFIX}" --libdir="${TP_PREFIX}/lib" CFLAGS="-fPIC" CXXFLAGS="-fPIC" --enable-static=yes --enable-shared=no

if [[ ${OS_ARCH} =~ "x86_64" ]]; then
    export CPU_CORES_NUM_x86=`cat /proc/cpuinfo |grep "cores" |wc -l`
    make -j${CPU_CORES_NUM_x86}
elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
    export CPU_CORES_NUM_arm=`cat /proc/cpuinfo |grep "architecture" |wc -l`
    make -j${CPU_CORES_NUM_arm}
else 
    echo "OS_ARCH: ${OS_ARCH} is unknown, set CPU_CORES_NUM=16 "
    export CPU_CORES_NUM=16
    make -j${CPU_CORES_NUM}
fi
make install

mkdir -p ${LIBRARY}/protobuf/lib
cp ${OPEN_SOURCE}/protobuf-c/protobuf-c-1.4.1/protobuf-c/.libs/libprotobuf-c.a ${LIBRARY}/protobuf/lib/
mkdir -p ${OPEN_SOURCE}/protobuf-c/include/
mkdir -p ${LIBRARY}/protobuf/protobuf-c/
cp ${OPEN_SOURCE}/protobuf-c/protobuf-c-1.4.1/protobuf-c/protobuf-c.h ${OPEN_SOURCE}/protobuf-c/include/
cp ${OPEN_SOURCE}/protobuf-c/protobuf-c-1.4.1/protobuf-c/protobuf-c.h ${LIBRARY}/protobuf/protobuf-c/

#openssl
rm -rf ${OPEN_SOURCE}/openssl || true
mkdir -p ${OPEN_SOURCE}/openssl
cp -rf ${OPEN_SOURCE}/openGauss-third_party/dependency/openssl/* ${OPEN_SOURCE}/openssl/
cd ${OPEN_SOURCE}/openssl
rm -rf openssl-3.0.9
mkdir -p openssl-3.0.9
tar -zxvf openssl-3.0.9.tar.gz -C openssl-3.0.9 --strip-components 1
# apply patches listed in patch_list (same semantics as build.py)
cd ${OPEN_SOURCE}/openssl/openssl-3.0.9
if [[ -f ../patch_list ]]; then
    while read -r line; do
        pathName=$(echo "${line}" | awk '{print $2}')
        [[ -z "${pathName}" ]] && continue
        patch -p1 < "../${pathName}"
    done < ../patch_list
fi
mkdir -p "${OPEN_SOURCE}/openssl/install"
./config --prefix="${OPEN_SOURCE}/openssl/install" shared -Wno-error
if [[ ${OS_ARCH} =~ "x86_64" ]]; then
    export CPU_CORES_NUM_x86=`cat /proc/cpuinfo |grep "cores" |wc -l`
    make -j${CPU_CORES_NUM_x86}
elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
    export CPU_CORES_NUM_arm=`cat /proc/cpuinfo |grep "architecture" |wc -l`
    make -j${CPU_CORES_NUM_arm}
else 
    echo "OS_ARCH: ${OS_ARCH} is unknown, set CPU_CORES_NUM=16 "
    export CPU_CORES_NUM=16
    make -j${CPU_CORES_NUM}
fi
make install
# OpenSSL installs to lib64 on 64-bit Linux by default; detect actual path
OPENSSL_INSTALL_LIB="${OPEN_SOURCE}/openssl/install/lib"
if [ -d "${OPEN_SOURCE}/openssl/install/lib64" ]; then
    OPENSSL_INSTALL_LIB="${OPEN_SOURCE}/openssl/install/lib64"
fi
mkdir -p ${OPEN_SOURCE}/openssl/include/
mkdir -p ${LIBRARY}/openssl/lib/
mkdir -p ${LIBRARY}/openssl/bin/
cp -rf ${OPEN_SOURCE}/openssl/openssl-3.0.9/include/* ${OPEN_SOURCE}/openssl/include/
cp -rf ${OPEN_SOURCE}/openssl/openssl-3.0.9/*.a ${LIBRARY}/openssl/lib
# Copy shared libraries and openssl binary for runtime packaging
cp -d ${OPENSSL_INSTALL_LIB}/libssl.so* ${LIBRARY}/openssl/lib/ 2>/dev/null || true
cp -d ${OPENSSL_INSTALL_LIB}/libcrypto.so* ${LIBRARY}/openssl/lib/ 2>/dev/null || true
cp -d ${OPEN_SOURCE}/openssl/install/bin/openssl ${LIBRARY}/openssl/bin/ 2>/dev/null || true
echo "copy lib finished"

# zlib (openEuler zlib spec layout)
cd ${OPEN_SOURCE}/zlib
rm -rf zlib-1.2.13
# zlib-1.2.13 sources are provided as .tar.xz in the openEuler package
tar -xJf zlib-1.2.13.tar.xz
apply_spec_patches_to_dir "${OPEN_SOURCE}/zlib/zlib-1.2.13"
cd ${OPEN_SOURCE}/zlib/zlib-1.2.13
mkdir -p ${OPEN_SOURCE}/zlib/include
mkdir -p ${LIBRARY}/zlib/lib
cp zconf.h zlib.h ${OPEN_SOURCE}/zlib/include
if [[ ${OS_ARCH} =~ "aarch64" ]]; then
    CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now,-z,noexecstack -march=armv8-a+crc' ./configure
else
    CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' ./configure
fi
make -sj
tar -cvf libz.tar libz.so*;cp libz.tar libz.so* ${LIBRARY}/zlib/lib/

#huawei_secure_c (build from openGauss-third_party Huawei_Secure_C component)
# copy Huawei_Secure_C component from third_party into platform directory
rm -rf ${PLATFORM}/Huawei_Secure_C
cp -r ${OPEN_SOURCE}/openGauss-third_party/platform/Huawei_Secure_C ${PLATFORM}
cd ${PLATFORM}/Huawei_Secure_C
sh build.sh -m all
# assume build.sh produces HuaweiSecureC with lib/ and include/ directories (as before)
mkdir -p ${PLATFORM}/huawei_security/include
mkdir -p ${LIBRARY}/huawei_security/lib
mkdir -p ${PLATFORM}/HuaweiSecureC/lib
cp ${PLATFORM}/Huawei_Secure_C/Huawei_Secure_C_V100R001C01SPC010B002/src/* ${PLATFORM}/HuaweiSecureC/lib/
cp ${PLATFORM}/Huawei_Secure_C/Huawei_Secure_C_V100R001C01SPC010B002/src/libsecurec* ${LIBRARY}/huawei_security/lib/
cp ${PLATFORM}/Huawei_Secure_C/Huawei_Secure_C_V100R001C01SPC010B002/include/* ${PLATFORM}/huawei_security/include/