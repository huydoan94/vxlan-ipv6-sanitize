#ifndef VXLAN_IPV6_SANITIZE_HELPERS_H
#define VXLAN_IPV6_SANITIZE_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

constexpr size_t DHCPV6_TRANSACTION_ID_LEN = 3U;
constexpr size_t NDP_OPTION_LEN_UNIT_OCTETS = 8U;

struct nd_option_header_wire {
	uint8_t type;
	uint8_t length_units;
} __attribute__((packed));

enum ipv6_packet_result {
	IPV6_PACKET_OK = 0,
	IPV6_PACKET_PASSTHROUGH,
	IPV6_PACKET_TRUNCATED,
};

/*
 * NFQUEUE exposes NFQA_PAYLOAD from skb->data. For bridge-family IPv6
 * packets, that starts at the IPv6 header. declared_len follows ip6_plen,
 * while captured_len includes any bytes NFQUEUE supplied after that boundary.
 */
struct ipv6_packet_view {
	uint8_t *data;
	struct ip6_hdr *header;
	uint8_t *declared_end;
	uint8_t *captured_end;
	size_t declared_len;
	size_t captured_len;
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
enum ipv6_packet_result
parse_nfqueue_ipv6_payload(uint8_t *payload, size_t payload_len,
                           struct ipv6_packet_view *view);
int ipv6_packet_remove(struct ipv6_packet_view *packet,
                       uint8_t *remove_start, size_t remove_len);

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
uint16_t udp_ipv6_checksum(const struct ip6_hdr *ip6h,
                           const uint8_t *udp, size_t udp_len);

#endif
