# vxlan-ipv6-sanitize

Small OpenWrt daemon that sanitizes IPv6 Router Advertisements and DHCPv6
replies received through VXLAN before they reach local clients.

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
 classify packet
   /    |    \
  v     v     v
 RA   DHCPv6 other
 |      |      |
 v      v      |
sanitize sanitize |
   \    /      |
    v  v        |
   NF_ACCEPT <---+
      |
      v
 Local bridge clients
```

## What it changes

Router Advertisements:

- Router Lifetime -> `0`
- RDNSS -> one local bridge ULA (duplicate addresses/options removed)
- DNS Search List (DNSSL, option 31) -> removed

DHCPv6 server replies (`547 -> 546`):

- DNS Recursive Name Server option 23 -> one local bridge ULA (duplicates removed)
- Domain Search List option 24 -> removed

Other packet contents are left unchanged. The daemon classifies each queued
packet as RA, DHCPv6, or unsupported before running a sanitizer. Malformed or
unsupported packets are accepted without modification.

## Build

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

The daemon listens on NFQUEUE `100`. For bridge-family queues, Linux exposes
the IPv6 packet through `NFQA_PAYLOAD`; the Ethernet header is carried
separately by NFQUEUE and is left unchanged by this daemon.

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

Enable verbose logging:

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
├── vxlan-ipv6-sanitize.c   daemon and packet sanitizers
├── helper.c                packet/network helpers
├── helper.h
├── logging.c               logging and log formatting
└── logging.h
```

## License

MIT
