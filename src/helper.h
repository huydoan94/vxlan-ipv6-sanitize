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

/*
 * NFQUEUE exposes NFQA_PAYLOAD from skb->data. For bridge-family IPv6
 * packets, that starts at the IPv6 header; the L2 header is a separate
 * NFQA_L2HDR attribute and is not part of nfq_get_payload().
 */
struct ipv6_packet_view {
	uint8_t *data;
	size_t len;
};

/*
 * In-place option-stream compactor. read points at the next source option and
 * write points at where the next kept option belongs.
 */
struct option_compactor {
	uint8_t *start;
	uint8_t *read;
	uint8_t *write;
};

uint16_t read_be16(const uint8_t *p);
int resolve_local_dns(uint32_t indev, uint32_t physindev,
                      struct in6_addr *dns,
                      char *source_ifname, size_t source_ifname_len);
int parse_nfqueue_ipv6_payload(uint8_t *payload, size_t payload_len,
                                struct ipv6_packet_view *view);

void option_compactor_init(struct option_compactor *compactor, uint8_t *start);
void option_compactor_keep(struct option_compactor *compactor,
                           size_t source_len);
void option_compactor_skip(struct option_compactor *compactor,
                           size_t source_len);
void option_compactor_keep_prefix(struct option_compactor *compactor,
                                  size_t keep_len, size_t source_len);
size_t option_compactor_output_len(const struct option_compactor *compactor);

uint16_t icmpv6_checksum(const struct ip6_hdr *ip6h,
                         const uint8_t *icmp, size_t icmp_len);

#endif
