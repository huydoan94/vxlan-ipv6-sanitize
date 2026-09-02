# vxlan-ipv6-sanitize

Small OpenWrt daemon that sanitizes IPv6 Router Advertisements and DHCPv6
server replies received through VXLAN before they reach local clients.

## Packet flow

```text
Remote VXLAN peer
      |
      v
   VXLAN port
      |
      v
bridge prerouting
      |
      v
  NFQUEUE 100
      |
      v
 libtins IPv6 parser
   /      |       \
  v       v        v
 RA     DHCPv6    other
 |        |         |
 v        v         |
sanitize sanitize   |
   \      /         |
    v    v          |
    verdict <--------+
      |
      v
 Local bridge clients
```

## What it changes

Router Advertisements:

- Router Lifetime -> `0`
- RDNSS -> one local ULA
- duplicate RDNSS addresses/options -> removed
- DNSSL option 31 -> removed
- PvD option 21 -> removed

DHCPv6 Advertise/Reply packets (`547 -> 546`):

- DNS Recursive Name Server option 23 -> one local ULA
- duplicate DNS addresses/options -> removed
- Domain Search List option 24 -> removed

The local DNS address is the first ULA (`fc00::/7`) found on the ingress
interface or its bridge master.

## Packet handling

- IPv6 extension-header traversal and transport discovery are delegated to libtins.
- Routing, AH, ESP, Mobility, jumbograms, and other unsupported layouts pass unchanged.
- Fragmented target RA/DHCPv6 packets are dropped.
- If the IPv6 declared length exceeds the bytes delivered by NFQUEUE, the
  packet is dropped.
- If IPv6 or UDP declares a shorter region than NFQUEUE captured, only the
  declared region is sanitized. Bytes after it are preserved unchanged.
- If UDP declares more bytes than are available, the packet is dropped.
- A valid incoming checksum remains valid after sanitization.
- An invalid incoming checksum remains deliberately invalid after sanitization.
- NFQUEUE checksum-not-ready packets receive a correct checksum after editing.
- DHCPv6 Authentication option 11 and SEND RSA Signature option 12 are left
  untouched. If a protected packet would require sanitization, it is dropped;
  if no change is needed, it passes unchanged.
- Other malformed or unsupported packets pass unchanged.

## Build

The daemon uses OpenWrt's `libtins` package for IPv6 protocol parsing, protocol
constants, interface/address access, formatting, and checksum helpers. It only
needs libtins' core library; libpcap support can be disabled in libtins
configuration if it is not otherwise needed on the target.

Add the package to your OpenWrt source tree, then run:

```sh
make package/vxlan-ipv6-sanitize/compile V=s
```

## Install

Install the generated `.ipk`, then enable and start the service:

```sh
/etc/init.d/vxlan-ipv6-sanitize enable
/etc/init.d/vxlan-ipv6-sanitize start
```

## nftables

The package does **not** install nftables rules. Configure NFQUEUE yourself.

An example is included at:

```text
examples/90-vxlan-ipv6-sanitize.nft
```

Example rules:

```nft
table bridge vxlan_ipv6_sanitize {
    chain vxlan_ingress {
        type filter hook prerouting priority filter; policy accept;

        meta iifkind "vxlan" icmpv6 type nd-router-advert \
            counter queue num 100 bypass

        meta iifkind "vxlan" udp sport 547 udp dport 546 \
            counter queue num 100 bypass
    }
}
```

The daemon accepts only bridge-family packets from NFQUEUE `100`. Linux exposes
the IPv6 packet through `NFQA_PAYLOAD`; bridge L2 metadata is kept separately by
the kernel.

## Configuration

OpenWrt configuration file:

```text
/etc/config/vxlan-ipv6-sanitize
```

Default:

```uci
config sanitizer 'main'
    option verbose '0'
```

Enable verbose packet logging:

```sh
uci set vxlan-ipv6-sanitize.main.verbose='1'
uci commit vxlan-ipv6-sanitize
/etc/init.d/vxlan-ipv6-sanitize restart
```

## Logs

```sh
logread -f -e vxlan-ipv6-sanitize
```

## Source layout

```text
src/
├── vxlan-ipv6-sanitize.cpp daemon and packet sanitizers
├── helper.cpp              packet/network helpers
├── helper.h
├── packet_parser.cpp       libtins IPv6 transport parser
├── packet_parser.h         parser interface
├── logging.cpp             logging and log formatting
└── logging.h
```

## License

MIT
