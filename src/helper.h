#ifndef VXLAN_IPV6_SANITIZE_HELPERS_H
#define VXLAN_IPV6_SANITIZE_HELPERS_H

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>
#include <netinet/ip6.h>


#define DHCPV6_TRANSACTION_ID_LEN 3U
#define NDP_OPTION_LEN_UNIT_OCTETS 8U

struct nd_option_header_wire {
	uint8_t type;
	uint8_t length_units;
} __attribute__((packed));

enum dhcpv6_message_type {
	DHCPV6_SOLICIT = 1,
	DHCPV6_ADVERTISE,
	DHCPV6_REQUEST,
	DHCPV6_CONFIRM,
	DHCPV6_RENEW,
	DHCPV6_REBIND,
	DHCPV6_REPLY,
	DHCPV6_RELEASE,
	DHCPV6_DECLINE,
	DHCPV6_RECONFIGURE,
	DHCPV6_INFORMATION_REQUEST,
	DHCPV6_RELAY_FORWARD,
	DHCPV6_RELAY_REPLY,
};

uint16_t read_be16(const uint8_t *p);
void write_be16(uint8_t *p, uint16_t value);

int resolve_local_dns(uint32_t indev, uint32_t physindev,
		      struct in6_addr *dns,
		      char *source_ifname, size_t source_ifname_len);
int locate_ipv6(const uint8_t *packet, size_t packet_len,
		size_t *ipv6_offset, size_t *ipv6_len);

int validate_nd_options(const uint8_t *options, size_t options_len);
uint16_t icmpv6_checksum(const struct ip6_hdr *ip6h,
			 const uint8_t *icmp, size_t icmp_len);

#endif
