#!/bin/sh

set -eu

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$TEST_DIR/.." && pwd)
BUILD_DIR=${BUILD_DIR:-"$TEST_DIR/build"}
CXX=${CXX:-g++}
LOCAL_LIBTINS_PREFIX="$TEST_DIR/build/libtins-host"
if [ -f "$LOCAL_LIBTINS_PREFIX/include/tins/ipv6.h" ]; then
	DEFAULT_LIBTINS_PREFIX=$LOCAL_LIBTINS_PREFIX
else
	DEFAULT_LIBTINS_PREFIX=/usr
fi
LIBTINS_PREFIX=${LIBTINS_PREFIX:-$DEFAULT_LIBTINS_PREFIX}
NFQUEUE_INCLUDE_DIR=${NFQUEUE_INCLUDE_DIR:-/usr/include}
NFNETLINK_INCLUDE_DIR=${NFNETLINK_INCLUDE_DIR:-$NFQUEUE_INCLUDE_DIR}
COVERAGE=${COVERAGE:-0}
SANITIZERS=${SANITIZERS:-0}

if [ ! -f "$LIBTINS_PREFIX/include/tins/constants.h" ]; then
	echo "libtins development headers not found under $LIBTINS_PREFIX/include" >&2
	echo "Build a native copy of OpenWrt's libtins: sh ./tests/build-host-libtins.sh" >&2
	exit 1
fi

if ! grep -q "struct fragment_header" "$LIBTINS_PREFIX/include/tins/ipv6.h" ||
	! grep -q "class invalid_ipv6_extension_header" "$LIBTINS_PREFIX/include/tins/exceptions.h"; then
	echo "The host libtins under $LIBTINS_PREFIX is older than the production libtins API." >&2
	echo "Build a matching native copy: sh ./tests/build-host-libtins.sh" >&2
	exit 1
fi

if [ ! -f "$NFQUEUE_INCLUDE_DIR/libnetfilter_queue/libnetfilter_queue.h" ]; then
	echo "libnetfilter_queue development headers not found under $NFQUEUE_INCLUDE_DIR" >&2
	echo "Ubuntu/Debian: sudo apt install libnetfilter-queue-dev" >&2
	exit 1
fi

if [ ! -f "$NFNETLINK_INCLUDE_DIR/libnfnetlink/libnfnetlink.h" ]; then
	echo "libnfnetlink development headers not found under $NFNETLINK_INCLUDE_DIR" >&2
	echo "Ubuntu/Debian: sudo apt install libnfnetlink-dev" >&2
	exit 1
fi

mkdir -p "$BUILD_DIR"
rm -f "$BUILD_DIR/unit-tests-unit_tests.gcda" \
	"$BUILD_DIR/unit-tests-unit_tests.gcno"

set --

if [ "$LIBTINS_PREFIX/include" != "/usr/include" ]; then
	set -- "$@" -isystem "$LIBTINS_PREFIX/include"
fi

if [ "$NFQUEUE_INCLUDE_DIR" != "/usr/include" ]; then
	set -- "$@" -isystem "$NFQUEUE_INCLUDE_DIR"
fi

if [ "$NFNETLINK_INCLUDE_DIR" != "/usr/include" ] &&
	[ "$NFNETLINK_INCLUDE_DIR" != "$NFQUEUE_INCLUDE_DIR" ]; then
	set -- "$@" -isystem "$NFNETLINK_INCLUDE_DIR"
fi

CXXFLAGS="-std=gnu++11 -O0 -g -Wall -Wextra -Wformat=2 -Wshadow -Werror"
LDFLAGS=""

if [ "$COVERAGE" -eq 1 ]; then
	CXXFLAGS="$CXXFLAGS --coverage"
	LDFLAGS="$LDFLAGS --coverage"
fi

if [ "$SANITIZERS" -eq 1 ]; then
	CXXFLAGS="$CXXFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
	LDFLAGS="$LDFLAGS -fsanitize=address,undefined"
fi

"$CXX" \
	$CXXFLAGS \
	-I"$PROJECT_DIR/src" \
	"$@" \
	-o "$BUILD_DIR/unit-tests" \
	"$TEST_DIR/unit_tests.cpp" \
	$LDFLAGS \
	-L"$LIBTINS_PREFIX/lib" \
	-ltins

"$BUILD_DIR/unit-tests"

if [ "$COVERAGE" -eq 1 ]; then
	(
		cd "$BUILD_DIR"
		gcov --branch-counts --branch-probabilities \
			unit-tests-unit_tests.gcno
	)
fi
