# Unit tests

The test executable includes the production translation units directly so it
can exercise file-local sanitizer and NFQUEUE callback branches without making
those implementation details public in the daemon build. NFQUEUE and selected
system calls are replaced with deterministic test doubles.

The suite covers:

- IPv6 NFQUEUE payload validation and in-place removal
- option compaction and checksum-state preservation
- IPv6 extension-header and transport policy
- RA validation, RDNSS rewriting/deduplication, DNSSL/PvD removal, SEND policy,
  checksums, logging, and compaction failures
- DHCPv6 envelope and option validation, DNS rewriting/deduplication, Domain
  List removal, Authentication policy, checksums, logging, and compaction
  failures
- NFQUEUE callback accept/drop/change/fail-open decisions
- daemon argument, setup, poll, receive, and cleanup paths
- formatting helpers, address lists, DUIDs, and transaction IDs

Run with installed development headers and libraries:

```sh
./tests/run-tests.sh
```

On Ubuntu or Debian, install the native host build dependencies first:

```sh
sudo apt update
sudo apt install build-essential cmake libnetfilter-queue-dev libnfnetlink-dev
```

Ubuntu's libtins package can be older than the API used by the production
OpenWrt package. When no compatible native libtins is available, the test runner
automatically prepares the OpenWrt package and builds a native copy from exactly
that source under `tests/build/libtins-host`:

```sh
./tests/run-tests.sh
```

The native build disables packet capture, 802.11, examples, and libtins' own
tests. The test runner selects the resulting local prefix automatically, so the
normal coverage command remains:

```sh
cd package/vxlan-ipv6-sanitize
COVERAGE=1 sh ./tests/run-tests.sh
```

Do not point the host test suite at OpenWrt's target staging directory. Those
libraries are built for the target router architecture and cannot be linked
into the test executable produced by the host compiler. Building the native
copy does not modify or replace the production OpenWrt library.

If libtins or libnetfilter_queue headers are in nonstandard locations:

```sh
LIBTINS_PREFIX=/path/to/libtins/prefix \
NFQUEUE_INCLUDE_DIR=/path/to/netfilter/includes \
NFNETLINK_INCLUDE_DIR=/path/to/nfnetlink/includes \
./tests/run-tests.sh
```

Generate GCC line and branch coverage:

```sh
COVERAGE=1 ./tests/run-tests.sh
```

Run with AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
SANITIZERS=1 ./tests/run-tests.sh
```

The suite is host-side. It does not replace an OpenWrt integration test that
loads the real nftables rule, sends packets through NFQUEUE 100, and verifies
the resulting bridge traffic.
