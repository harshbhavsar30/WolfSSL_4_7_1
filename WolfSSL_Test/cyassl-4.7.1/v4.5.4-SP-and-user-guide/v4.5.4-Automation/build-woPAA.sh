#!/bin/sh

WORKING_DIR=$(eval "pwd")
TOOLCHAIN_ROOT=/opt/poky/3.0
# change based on release (wolfssl-x.x.x-commercial-fips-ARMv8-A-v2)
WOLF_DIR="$WORKING_DIR"/XXX-fips-test
# change based on target device IP
DEVICE_IP="192.168.28.155"
REMOTE_SHARED_LIB_DIR="/kernel/wolf-shared-lib-dir"

step_1_configure_library(){
    # source the environment setup file
    echo ". ${TOOLCHAIN_ROOT}/environment-setup-aarch64-poky-linux"
    . "${TOOLCHAIN_ROOT}"/environment-setup-aarch64-poky-linux

#    export CC="aarch64-poky-linux-gcc --host=aarch64-poky-linux --sysroot=$TOOLCHAIN_ROOT/sysroots/aarch64-poky-linux"

    # change to the wolfSSL FIPS root directory (adjust WOLF_DIR on new releases)
    cd $WOLF_DIR || exit 5

    # The CPPFLAGS to build with
    LOCAL_CPPFLAGS="-DSIZEOF_LONG=8 -DSIZEOF_LONG_LONG=8 -DWOLFSSL_CALLBACKS -DSESSION_CERTS -DSHOW_CERTS -DHAVE_EX_DATA -DWOLFSSL_VERIFY_CB_ALL_CERTS -DWOLFSSL_STATIC_RSA -DWOLFSSL_PUBLIC_MP -DTFM_NO_ASM -DHAVE_FORCE_FIPS_FAILURE -DFP_MAX_BITS=8192 -DACVP_VECTOR_TESTING"
    export CPPFLAGS="${LOCAL_CPPFLAGS}"

    LOCAL_LDFLAGS="-Wl,-Map=wolf_output.map"
    export LDFLAGS="${LOCAL_LDFLAGS}"

    # A custom library install location to avoid linking libwolfssl.so included in original jol-sdk delivery that was not FIPS enabled.
    INSTALL_LOCATION="${WORKING_DIR}/FIPS-install-dir"

    # Configure and build shared library
    # ${CONFIGURE_FLAGS} is set in /host/pkgs/sdk-arm.../environment-setup... use it
    # to get the right environment build settings.
    echo "Running configure script..."
    CONFIG_RESULT=$(eval "./configure ${CONFIGURE_FLAGS} --prefix=${INSTALL_LOCATION} --enable-fips=v2 --enable-opensslextra --enable-opensslall --enable-keygen --disable-examples --enable-shared --disable-static --disable-examples --disable-crypttests --enable-sha3 --enable-dsa")

    RESULT=$?
    echo "CONFIG RESULT = $RESULT"
    [ $RESULT -ne 0 ] && echo "Configuration Failed" && exit 1
    echo "Running make clean..."
    TMP=$(eval "make uninstall")
    TMP=$(eval "make clean")
    echo "Running make..."
    TMP=$(eval "make")
    RESULT=$?
    echo "MAKE RESULT = $RESULT"
    [ $RESULT -ne 0 ] && echo "Build Failed" && exit 1
    echo "Installing locally..."
    TMP=$(eval "make install")


    cd "${WORKING_DIR}" || exit 5

    echo "Confirm shared object:"
    ls -la "${INSTALL_LOCATION}"/lib
    echo "Copy lib to device:"
    echo "scp ${INSTALL_LOCATION}/lib/libwolfssl.so.24 root@${DEVICE_IP}:/kernel/wolf-shared-lib-dir/libwolfssl.so.24"
    sshpass -p 'root' scp "${INSTALL_LOCATION}"/lib/libwolfssl.so.24 root@"${DEVICE_IP}":"${REMOTE_SHARED_LIB_DIR}"/libwolfssl.so.24
}

step_2_build_app(){
    # Build indicated application
    if [ -z "$1" ]; then

        echo "Not option presented, only building library"

    elif [ ! -z "$1" ] && [ "$1" = "benchmark" ]; then

        build_and_scp_benchmark_app

    elif [ ! -z "$1" ] && [ "$1" = "test" ]; then

        build_and_scp_test_app

    elif [ ! -z "$1" ] && [ "$1" = "aes" ]; then

        build_and_scp_aes_app

# for use by wolfSSL only
#    elif [ ! -z "$1" ] && [ "$1" = "harness" ]; then
#
#        build_and_scp_harness_app
#
#    elif [ ! -z "$1" ] && [ "$1" = "optest" ]; then
#
#        build_and_scp_optest_app

    elif [ ! -z "$1" ]; then

        echo "Invalid option supplied: \"$1\""

    fi
}

step_3_get_new_hash(){
    # Now that apps are copied over lets SSH in and run the test app wolf-test to
    # get the new hash, captured in a variable for extraction

    if [ ! "$1" = "aes" ]; then
        RETURN_TO_DIR=$(eval "pwd")
        cd "${WORKING_DIR}" || exit 5
        build_and_scp_aes_app
        cd "${RETURN_TO_DIR}"
    fi

    REMOTE_OUTPUT=$(eval "sshpass -p 'root' ssh -t root@${DEVICE_IP} << EOF
    export LD_LIBRARY_PATH=${REMOTE_SHARED_LIB_DIR}
    cd /kernel
    ./aes_encrypt_decrypt
    exit
    EOF")

    NEW_HASH=$(echo "$REMOTE_OUTPUT" | sed -n 's/hash = \(.*\)/\1/p')
    echo "NEW HASH: $NEW_HASH"

    if test "$NEW_HASH"; then
        if ! sed -i.bak "s/^\".*\";/\"$NEW_HASH\";/" "${WOLF_DIR}"/wolfcrypt/src/fips_test.c; then
            echo "Couldn't update the test file."
            exit 5
        fi
    else
        echo "No new hash detected, exiting with SUCCESS"
        echo "Please login to the device and run whatever tests you desire"
        exit 0
    fi

    step_1_configure_library
    echo "Rebuilding all apps since hash changed"
    rm wolf-test wolf-benchmark aes_encrypt_decrypt
    rm *.o
    build_and_scp_test_app
    build_and_scp_benchmark_app
    build_and_scp_aes_app
#    build_and_scp_harness_app
}

build_and_scp_test_app(){
    echo "scp wolf-test root@${DEVICE_IP}:/kernel"
    $CC "${WOLF_DIR}"/wolfcrypt/test/test.c -o wolf-test -I"${INSTALL_LOCATION}"/include -I"${INSTALL_LOCATION}"/include/wolfssl -I"${WOLF_DIR}" -L"${INSTALL_LOCATION}"/lib -lwolfssl -lm
    [ $? -ne 0 ] && echo "building test app failed" && exit 1
    sshpass -p 'root' scp wolf-test root@${DEVICE_IP}:/kernel
}

build_and_scp_benchmark_app(){
    echo "scp wolf-benchmark root@${DEVICE_IP}:/kernel"
    $CC "${WOLF_DIR}"/wolfcrypt/benchmark/benchmark.c -o wolf-benchmark -I"${INSTALL_LOCATION}"/include -I"${INSTALL_LOCATION}"/include/wolfssl -I"${WOLF_DIR}" -L"${INSTALL_LOCATION}"/lib -lwolfssl -lm
    [ $? -ne 0 ] && echo "building benchmark app failed" && exit 1
    sshpass -p 'root' scp wolf-benchmark root@${DEVICE_IP}:/kernel
}

build_and_scp_aes_app(){
    echo "scp aes_encrypt_decrypt root@${DEVICE_IP}:/kernel"
    $CC aes_encrypt_decrypt.c -o aes_encrypt_decrypt -I"${INSTALL_LOCATION}"/include -I"${INSTALL_LOCATION}"/include/wolfssl -I"${WOLF_DIR}" -L"${INSTALL_LOCATION}"/lib -lwolfssl -lm
    [ $? -ne 0 ] && echo "building aes app failed" && exit 1
    sshpass -p 'root' scp aes_encrypt_decrypt root@${DEVICE_IP}:/kernel
}

ACVP_DIR="$WORKING_DIR"/fips/wolfACVP

# for use by wolfSSL only
#build_and_scp_harness_app(){
#    echo "Building FIPS test harness"
#    cd "${ACVP_DIR}" || exit 5
#    ACVP_CFLAGS="-I${INSTALL_LOCATION}/include -I$ACVP_DIR -g"
#    ACVP_LDFLAGS="-L${INSTALL_LOCATION}/lib -Wl,-Map=wolf_output.map"
#    export CFLAGS="${ACVP_CFLAGS}"
#    export LDFLAGS="${ACVP_LDFLAGS}"
#    export CPPFLAGS=""
#    ./autogen.sh
#    ./configure --host=aarch64-poky-linux --disable-client --disable-tests 
#    make clean
#    make
#    [ $? -ne 0 ] && echo "building test harness app failed" && exit 1
#    sshpass -p 'root' scp "${ACVP_DIR}"/wolfacvp_client root@"${DEVICE_IP}":/kernel/wolfacvp_client
#}
#
#build_and_scp_optest_app(){
#    echo "Building operational test"
#    cd "${WORKING_DIR}"/fips/op_test || exit 5
#    make clean
#    make
#    [ $? -ne 0 ] && echo "building operational test app failed" && exit 1
#    sshpass -p 'root' scp optest root@${DEVICE_IP}:/kernel
#}

# detect if building lib:
if [ ! -z "$2" ] && [ "$2" = "with-lib" ]; then
    step_1_configure_library
elif [ ! -z "$2" ]; then
    echo "Skipping re-build of library, just recompiling app ${1}"
else
    step_1_configure_library
fi

step_2_build_app "${1}" "${2}"
step_3_get_new_hash "${1}" "${2}"
