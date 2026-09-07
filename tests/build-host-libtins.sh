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
MAKE=${MAKE:-make}

find_libtins_source()
{
	find "$OPENWRT_ROOT/build_dir" \
		-type f \
		-path '*/include/tins/ipv6.h' \
		-print 2>/dev/null |
	while IFS= read -r ipv6_header; do
		candidate=${ipv6_header%/include/tins/ipv6.h}
		if [ -f "$candidate/CMakeLists.txt" ] &&
			grep -q "struct fragment_header" "$ipv6_header" 2>/dev/null &&
			grep -q "class invalid_ipv6_extension_header" "$candidate/include/tins/exceptions.h" 2>/dev/null; then
			CDPATH= cd -- "$candidate"
			pwd -P
			break
		fi
	done
}

if [ -z "$LIBTINS_SOURCE_DIR" ]; then
	LIBTINS_SOURCE_DIR=$(find_libtins_source)
fi

if [ -z "$LIBTINS_SOURCE_DIR" ]; then
	echo "Preparing OpenWrt's libtins source for the native test build..." >&2
	if ! "$MAKE" \
		-C "$OPENWRT_ROOT" \
		package/feeds/packages/libtins/prepare \
		V=s; then
		echo "Could not prepare OpenWrt's libtins package." >&2
		echo "Make sure its feed recipe is installed:" >&2
		echo "  ./scripts/feeds install libtins" >&2
		exit 1
	fi

	LIBTINS_SOURCE_DIR=$(find_libtins_source)
fi

if [ -z "$LIBTINS_SOURCE_DIR" ] || [ ! -f "$LIBTINS_SOURCE_DIR/CMakeLists.txt" ]; then
	echo "OpenWrt's extracted libtins source with the required API was not found." >&2
	echo "Look for the extracted header with:" >&2
	echo "  find build_dir -path '*/include/tins/ipv6.h' -print" >&2
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
