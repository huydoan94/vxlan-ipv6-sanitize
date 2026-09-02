#ifndef VXLAN_IPV6_SANITIZE_PACKET_PARSER_H
#define VXLAN_IPV6_SANITIZE_PACKET_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum ipv6_transport_result {
	IPV6_TRANSPORT_FOUND = 0,
	IPV6_TRANSPORT_OTHER,
	IPV6_TRANSPORT_UNSUPPORTED,
	IPV6_TRANSPORT_MALFORMED,
};

struct ipv6_transport_view {
	uint8_t protocol;
	uint8_t *header;
	size_t len;
	bool fragmented;
};

enum ipv6_transport_result
parse_ipv6_transport(uint8_t *packet, size_t packet_len,
                     struct ipv6_transport_view *transport);

#endif
