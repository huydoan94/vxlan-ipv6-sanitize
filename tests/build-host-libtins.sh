#!/bin/sh

set -eu

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$TEST_DIR/.." && pwd)
OPENWRT_ROOT=${OPENWRT_ROOT:-$(CDPATH= cd -- "$PROJECT_DIR/../.." && pwd)}
LIBTINS_SOURCE_DIR=${LIBTINS_SOURCE_DIR:-}
HOST_LIBTINS_BUILD_DIR=${HOST_LIBTINS_BUILD_DIR:-"$TEST_DIR/build/libtins-build"}
DEFAULT_HOST_LIBTINS_PREFIX="$TEST_DIR/build/libtins-host"
HOST_LIBTINS_PREFIX=${HOST_LIBTINS_PREFIX:-$DEFAULT_HOST_LIBTINS_PREFIX}
CMAKE=${CMAKE:-cmake}

if [ -z "$LIBTINS_SOURCE_DIR" ]; then
	LIBTINS_SOURCE_DIR=$(
		find "$OPENWRT_ROOT/build_dir" \
			-type f \
			-path '*/libtins-*/CMakeLists.txt' \
			-print 2>/dev/null |
		while IFS= read -r cmake_file; do
			candidate=${cmake_file%/CMakeLists.txt}
			if grep -q "struct fragment_header" "$candidate/include/tins/ipv6.h" 2>/dev/null &&
				grep -q "class invalid_ipv6_extension_header" "$candidate/include/tins/exceptions.h" 2>/dev/null; then
				CDPATH= cd -- "$candidate"
				pwd -P
				break
			fi
		done
	)
fi

if [ -z "$LIBTINS_SOURCE_DIR" ] || [ ! -f "$LIBTINS_SOURCE_DIR/CMakeLists.txt" ]; then
	echo "OpenWrt's extracted libtins source with the required API was not found." >&2
	echo "Prepare it from the OpenWrt root, then retry:" >&2
	echo "  make package/feeds/packages/libtins/prepare V=s" >&2
	exit 1
fi

if ! command -v "$CMAKE" >/dev/null 2>&1; then
	echo "cmake is required: sudo apt install cmake" >&2
	exit 1
fi

if command -v nproc >/dev/null 2>&1; then
	DEFAULT_JOBS=$(nproc)
else
	DEFAULT_JOBS=1
fi
JOBS=${JOBS:-$DEFAULT_JOBS}

"$CMAKE" \
	-S "$LIBTINS_SOURCE_DIR" \
	-B "$HOST_LIBTINS_BUILD_DIR" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX="$HOST_LIBTINS_PREFIX" \
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
	-DLIBTINS_BUILD_EXAMPLES=OFF \
	-DLIBTINS_BUILD_SHARED=OFF \
	-DLIBTINS_BUILD_TESTS=OFF \
	-DLIBTINS_ENABLE_ACK_TRACKER=OFF \
	-DLIBTINS_ENABLE_CXX11=ON \
	-DLIBTINS_ENABLE_DOT11=OFF \
	-DLIBTINS_ENABLE_PCAP=OFF \
	-DLIBTINS_ENABLE_TCP_STREAM_CUSTOM_DATA=OFF \
	-DLIBTINS_ENABLE_WPA2=OFF

"$CMAKE" \
	--build "$HOST_LIBTINS_BUILD_DIR" \
	--parallel "$JOBS"

"$CMAKE" \
	--install "$HOST_LIBTINS_BUILD_DIR"

echo "Native libtins installed under $HOST_LIBTINS_PREFIX"
if [ "$HOST_LIBTINS_PREFIX" = "$DEFAULT_HOST_LIBTINS_PREFIX" ]; then
	echo "The unit-test runner will select it automatically."
else
	echo "Run tests with LIBTINS_PREFIX=$HOST_LIBTINS_PREFIX"
fi
