# vxlan-ipv6-sanitize 1.2.2

Low-memory C NFQUEUE sanitizer for IPv6 configuration traffic received from
VXLAN bridge ports on OpenWrt.

The daemon rewrites only the IPv6 configuration information that can cause a
remote VXLAN site to become this site's DNS/default-router authority, while
leaving address/prefix information intact.

## Packet path

The package installs a firewall4 `ruleset-post` drop-in that creates a separate
`bridge`-family nftables table:

- hook: `prerouting`
- input selector: `meta iifkind "vxlan"`
- queue: NFQUEUE `100`
- queued traffic only:
  - ICMPv6 Router Advertisements
  - direct DHCPv6 server-to-client packets (`547 -> 546`)

`bridge prerouting` is intentional.  A VXLAN-decapsulated Ethernet frame reaches
this hook once, before the bridge FDB/flooding decision.  Using `bridge forward`
would potentially queue multiple flooded copies of the same multicast/broadcast
advertisement.

The nftables rules use `queue num 100 bypass`, so packets pass unchanged when no
userspace listener is attached.  The daemon also enables
`NFQA_CFG_F_FAIL_OPEN`, so packets pass unchanged if the kernel NFQUEUE itself
fills.

The firewall4 automatic include mechanism must be enabled (the OpenWrt default):

    uci get firewall.@defaults[0].auto_includes

After installing/upgrading the package, reload firewall4 once:

    /etc/init.d/firewall reload

Verify the interception table with:

    nft list table bridge vxlan_ipv6_sanitize

## Runtime rewrite policy

Remote Router Advertisements:

- Router Lifetime -> `0`
- every RDNSS server address -> local ingress bridge ULA
- PIO, Route Information, MTU, DNSSL, flags, lifetimes, option ordering, and all
  unrelated bytes are preserved

Remote direct DHCPv6 server-to-client messages (`547 -> 546`):

- DNS Recursive Name Server option 23 -> local ingress bridge ULA
- IA_NA, IAADDR, Client ID, Server ID, lifetimes, option ordering, and all other
  options are preserved
- relay messages are not rewritten

The local DNS address is discovered from the NFQUEUE ingress device.  For a
VXLAN bridge port, the daemon first checks the port and then its bridge master
for a ULA (`fc00::/7`).

## Libraries

- `libnetfilter_queue`:
  - NFQUEUE receive/verdict handling
  - IPv6 header validation
  - IPv6 extension-header traversal
  - UDP header/payload validation helpers
  - DHCPv6 DNS payload mangling
  - UDP/IPv6 checksum recalculation
- `libndp`:
  - Router Advertisement typed Router Lifetime access
  - Neighbor Discovery option discovery
  - RDNSS option/address iteration

OpenWrt 25.12 carries libnetfilter_queue 1.0.5 and a modern nftables/kernel
stack suitable for this implementation.

## Source layout

- `vxlan-ipv6-sanitize.c`: daemon lifecycle, NFQUEUE callback, and RA/DHCPv6 sanitizers
- `helper.c` / `helper.h`: reusable packet, address, formatting, and checksum helpers
- `logging.c` / `logging.h`: verbose/error logging and error-string formatting

## Small manual surface that remains

There is no suitable lightweight DHCPv6 C parser library in the OpenWrt runtime
set, and libnetfilter_queue has no public ICMPv6 checksum helper.  The daemon
therefore retains only:

- a small Ethernet/VLAN-to-IPv6 locator for bridge-family NFQUEUE payloads;
- generic ND-option structural validation before libndp iteration;
- the top-level DHCPv6 TLV iterator for Client ID and option 23;
- one ICMPv6 checksum routine for Router Advertisements;
- ingress-interface/bridge-master ULA discovery.

IPv6 jumbograms are outside scope.  Malformed or unsupported packets are always
accepted unchanged.

## Logging

Quiet by default. Errors always go to stderr/logd. Enable verbose operational
logging using either:

    /usr/sbin/vxlan-ipv6-sanitize -v

or:

    uci set vxlan-ipv6-sanitize.main.verbose='1'
    uci commit vxlan-ipv6-sanitize
    /etc/init.d/vxlan-ipv6-sanitize restart

Verbose RA records include source/destination, Router Lifetime before/after,
and RDNSS before/after. DHCPv6 records include source/destination, transaction
ID, Client ID, Ethernet MAC when present in DUID-LLT/DUID-LL, and DNS
before/after. OpenWrt logd supplies the event timestamp.

## Useful verification

Watch daemon decisions:

    logread -f -e vxlan-ipv6-sanitize

Watch nftables counters:

    watch -n1 'nft list table bridge vxlan_ipv6_sanitize'

For an RA arriving over VXLAN, the expected verbose result is Router Lifetime
changing to zero and each advertised RDNSS address changing to the ULA assigned
to the local bridge master.
