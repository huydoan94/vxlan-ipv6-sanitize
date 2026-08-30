#define _GNU_SOURCE

#include "helper.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ndp.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define DUID_LLT 1U
#define DUID_LL 3U
#define HWTYPE_ETHERNET 1U
#define IPV6_ULA_PREFIX_MASK 0xfeU
#define IPV6_ULA_PREFIX_VALUE 0xfcU
#define IPV6_PSEUDO_RESERVED_LEN 3U
#define SYSFS_LINK_BUFSIZE 256U
#define DESTINATION_TEXT_BUFSIZE \
	(INET6_ADDRSTRLEN + sizeof("(all-dhcp-agents)"))

struct vlan_tag_wire {
	uint16_t tci;
	uint16_t encapsulated_proto;
} __attribute__((packed));

struct duid_llt_ethernet_wire {
	uint16_t type;
	uint16_t hardware_type;
	uint32_t time;
	uint8_t mac[ETH_ALEN];
} __attribute__((packed));

struct duid_ll_ethernet_wire {
	uint16_t type;
	uint16_t hardware_type;
	uint8_t mac[ETH_ALEN];
} __attribute__((packed));

struct ipv6_pseudo_header {
	struct in6_addr source;
	struct in6_addr destination;
	uint32_t payload_length;
	uint8_t reserved[IPV6_PSEUDO_RESERVED_LEN];
	uint8_t next_header;
} __attribute__((packed));

uint16_t read_be16(const uint8_t *p)
{
	uint16_t network_value;

	memcpy(&network_value, p, sizeof(network_value));
	return ntohs(network_value);
}

uint32_t read_be24(const uint8_t *p)
{
	uint32_t value = 0;
	size_t i;

	for (i = 0; i < DHCPV6_TRANSACTION_ID_LEN; i++)
		value = (value << CHAR_BIT) | p[i];

	return value;
}

void write_be16(uint8_t *p, uint16_t value)
{
	uint16_t network_value = htons(value);

	memcpy(p, &network_value, sizeof(network_value));
}

static bool is_ula(const struct in6_addr *addr)
{
	return (addr->s6_addr[0] & IPV6_ULA_PREFIX_MASK) == IPV6_ULA_PREFIX_VALUE;
}

static int get_bridge_master(const char *ifname, char *master, size_t master_len)
{
	char path[SYSFS_LINK_BUFSIZE];
	char target[SYSFS_LINK_BUFSIZE];
	const char *base;
	ssize_t n;

	if (snprintf(path, sizeof(path), "/sys/class/net/%s/master", ifname) >=
	    (int)sizeof(path))
		return -1;

	n = readlink(path, target, sizeof(target) - 1);
	if (n < 0)
		return -1;

	target[n] = '\0';
	base = strrchr(target, '/');
	base = base ? base + 1 : target;

	if (*base == '\0' || strlen(base) >= master_len)
		return -1;

	strcpy(master, base);
	return 0;
}

static int find_ula_on_interface(const char *ifname, struct in6_addr *result)
{
	struct ifaddrs *ifas = NULL;
	struct ifaddrs *ifa;
	int found = -1;

	if (getifaddrs(&ifas) < 0)
		return -1;

	for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
		const struct sockaddr_in6 *sin6;

		if (ifa->ifa_addr == NULL)
			continue;
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
		if (!is_ula(&sin6->sin6_addr))
			continue;

		*result = sin6->sin6_addr;
		found = 0;
		break;
	}

	freeifaddrs(ifas);
	return found;
}

int resolve_local_dns(uint32_t indev, uint32_t physindev,
			     struct in6_addr *dns,
			     char *source_ifname, size_t source_ifname_len)
{
	char ifname[IF_NAMESIZE];
	char master[IF_NAMESIZE];
	uint32_t candidates[] = { indev, physindev };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(candidates); i++) {
		uint32_t ifindex = candidates[i];

		if (ifindex == 0)
			continue;
		if (i > 0 && candidates[i] == candidates[0])
			continue;
		if (if_indextoname(ifindex, ifname) == NULL)
			continue;

		if (find_ula_on_interface(ifname, dns) == 0) {
			snprintf(source_ifname, source_ifname_len, "%s", ifname);
			return 0;
		}

		if (get_bridge_master(ifname, master, sizeof(master)) == 0 &&
		    find_ula_on_interface(master, dns) == 0) {
			snprintf(source_ifname, source_ifname_len, "%s", master);
			return 0;
		}
	}

	return -1;
}

/*
 * NFQUEUE bridge-family payloads can be either L3-only or Ethernet frames.
 * libnetfilter_queue's AF_BRIDGE pkt_buff parser does not cover VLAN stacks,
 * so keep only this small L2 locator and hand the IPv6 packet itself to the
 * library for all subsequent protocol work.
 */
static bool has_ipv6_version(const uint8_t *packet)
{
	return (packet[0] & IPV6_VERSION_MASK) == IPV6_VERSION;
}

static bool is_vlan_ethertype(uint16_t ethertype)
{
	return ethertype == ETH_P_8021Q ||
	       ethertype == ETH_P_8021AD ||
	       ethertype == ETH_P_QINQ1;
}

int locate_ipv6(const uint8_t *packet, size_t packet_len,
		       size_t *ipv6_offset, size_t *ipv6_len)
{
	const size_t ethernet_proto_offset = offsetof(struct ethhdr, h_proto);
	const size_t vlan_proto_offset =
		offsetof(struct vlan_tag_wire, encapsulated_proto);
	const size_t ipv6_payload_len_offset = offsetof(struct ip6_hdr, ip6_plen);
	uint16_t ethertype;
	size_t off;
	uint16_t payload_len;

	if (packet_len >= sizeof(struct ip6_hdr) && has_ipv6_version(packet)) {
		off = 0;
	} else {
		if (packet_len < sizeof(struct ethhdr))
			return -1;

		ethertype = read_be16(packet + ethernet_proto_offset);
		off = sizeof(struct ethhdr);

		while (is_vlan_ethertype(ethertype)) {
			if (off + sizeof(struct vlan_tag_wire) > packet_len)
				return -1;

			ethertype = read_be16(packet + off + vlan_proto_offset);
			off += sizeof(struct vlan_tag_wire);
		}

		if (ethertype != ETH_P_IPV6)
			return -1;
	}

	if (off + sizeof(struct ip6_hdr) > packet_len)
		return -1;
	if (!has_ipv6_version(packet + off))
		return -1;

	payload_len = read_be16(packet + off + ipv6_payload_len_offset);
	if (payload_len == 0)
		return -1; /* IPv6 jumbograms are outside this daemon's scope. */

	*ipv6_len = sizeof(struct ip6_hdr) + (size_t)payload_len;
	if (*ipv6_len > packet_len - off)
		return -1;

	*ipv6_offset = off;
	return 0;
}

static void format_mac(const uint8_t *mac, char *buf, size_t len)
{
	size_t i;
	size_t used = 0;

	if (len == 0)
		return;

	buf[0] = '\0';
	for (i = 0; i < ETH_ALEN; i++) {
		int written = snprintf(buf + used, len - used, "%s%02x",
				       i == 0 ? "" : ":", mac[i]);

		if (written < 0 || (size_t)written >= len - used)
			return;
		used += (size_t)written;
	}
}

static bool ipv6_equals_literal(const struct in6_addr *addr,
				const char *literal)
{
	struct in6_addr expected;

	if (inet_pton(AF_INET6, literal, &expected) != 1)
		return false;

	return memcmp(addr, &expected, sizeof(expected)) == 0;
}

static void format_destination(const struct in6_addr *addr,
			       char *buf, size_t len)
{
	static const char all_nodes[] = "ff02::1";
	static const char all_dhcp_agents[] = "ff02::1:2";
	char ip[INET6_ADDRSTRLEN];

	if (inet_ntop(AF_INET6, addr, ip, sizeof(ip)) == NULL)
		snprintf(ip, sizeof(ip), "?");

	if (ipv6_equals_literal(addr, all_nodes))
		snprintf(buf, len, "%s(all-nodes)", ip);
	else if (ipv6_equals_literal(addr, all_dhcp_agents))
		snprintf(buf, len, "%s(all-dhcp-agents)", ip);
	else
		snprintf(buf, len, "%s", ip);
}

void format_endpoints(const uint8_t *packet, size_t packet_len,
			     size_t ipv6_offset, const struct ip6_hdr *ip6h,
			     char *buf, size_t len)
{
	char src[INET6_ADDRSTRLEN];
	char dst[DESTINATION_TEXT_BUFSIZE];

	if (inet_ntop(AF_INET6, &ip6h->ip6_src, src, sizeof(src)) == NULL)
		snprintf(src, sizeof(src), "?");
	format_destination(&ip6h->ip6_dst, dst, sizeof(dst));

	if (ipv6_offset >= sizeof(struct ethhdr) &&
	    packet_len >= sizeof(struct ethhdr)) {
		char src_mac[MAC_TEXT_BUFSIZE];
		char dst_mac[MAC_TEXT_BUFSIZE];

		format_mac(packet + offsetof(struct ethhdr, h_source),
			   src_mac, sizeof(src_mac));
		format_mac(packet + offsetof(struct ethhdr, h_dest),
			   dst_mac, sizeof(dst_mac));
		snprintf(buf, len, "from=%s(%s) to=%s(%s)",
			 src, src_mac, dst, dst_mac);
		return;
	}

	snprintf(buf, len, "from=%s to=%s", src, dst);
}

void addr_list_init(struct addr_list *list)
{
	snprintf(list->buf, sizeof(list->buf), "[");
	list->len = strlen(list->buf);
	list->first = true;
	list->truncated = false;
}

void addr_list_append(struct addr_list *list, const struct in6_addr *addr)
{
	char ip[INET6_ADDRSTRLEN];
	char piece[INET6_ADDRSTRLEN + sizeof(",")];
	int n;

	if (list->truncated)
		return;
	if (inet_ntop(AF_INET6, addr, ip, sizeof(ip)) == NULL)
		snprintf(ip, sizeof(ip), "?");

	n = snprintf(piece, sizeof(piece), "%s%s", list->first ? "" : ",", ip);
	if (n < 0 || (size_t)n >= sizeof(piece) ||
	    list->len + (size_t)n + sizeof(",...]") > sizeof(list->buf)) {
		list->truncated = true;
		return;
	}

	memcpy(list->buf + list->len, piece, (size_t)n);
	list->len += (size_t)n;
	list->buf[list->len] = '\0';
	list->first = false;
}

const char *addr_list_finish(struct addr_list *list)
{
	const char *suffix = list->truncated ? ",...]" : "]";
	size_t suffix_len = strlen(suffix);

	if (list->first && list->truncated)
		suffix = "...]";

	suffix_len = strlen(suffix);
	if (list->len + suffix_len < sizeof(list->buf)) {
		memcpy(list->buf + list->len, suffix, suffix_len + 1);
		list->len += suffix_len;
	} else {
		list->buf[sizeof(list->buf) - sizeof("]")] = ']';
		list->buf[sizeof(list->buf) - 1] = '\0';
	}

	return list->buf;
}

void format_hex(const uint8_t *data, size_t data_len,
		       char *buf, size_t buf_len)
{
	static const char hex[] = "0123456789abcdef";
	static const char ellipsis[] = "...";
	const unsigned int nibble_bits = CHAR_BIT / 2U;
	const uint8_t low_nibble_mask = (uint8_t)((1U << nibble_bits) - 1U);
	size_t i;
	size_t out = 0;

	if (buf_len == 0)
		return;

	for (i = 0; i < data_len; i++) {
		if (buf_len - out <= sizeof("ff") - 1U)
			break;
		buf[out++] = hex[data[i] >> nibble_bits];
		buf[out++] = hex[data[i] & low_nibble_mask];
	}

	if (i < data_len && sizeof(ellipsis) <= buf_len - out) {
		memcpy(buf + out, ellipsis, sizeof(ellipsis) - 1U);
		out += sizeof(ellipsis) - 1U;
	}
	buf[out] = '\0';
}

void duid_ethernet_mac(const uint8_t *duid, size_t len,
			      char *buf, size_t buf_len)
{
	const uint8_t *mac = NULL;
	uint16_t duid_type;
	uint16_t hw_type;

	if (buf_len == 0)
		return;
	buf[0] = '\0';

	if (len < offsetof(struct duid_ll_ethernet_wire, mac))
		return;

	duid_type = read_be16(duid + offsetof(struct duid_ll_ethernet_wire, type));
	hw_type = read_be16(duid +
			     offsetof(struct duid_ll_ethernet_wire, hardware_type));
	if (hw_type != HWTYPE_ETHERNET)
		return;

	if (duid_type == DUID_LLT && len == sizeof(struct duid_llt_ethernet_wire))
		mac = duid + offsetof(struct duid_llt_ethernet_wire, mac);
	else if (duid_type == DUID_LL && len == sizeof(struct duid_ll_ethernet_wire))
		mac = duid + offsetof(struct duid_ll_ethernet_wire, mac);

	if (mac != NULL)
		format_mac(mac, buf, buf_len);
}

const char *dhcpv6_msg_name(uint8_t type)
{
	switch (type) {
	case DHCPV6_SOLICIT:             return "Solicit";
	case DHCPV6_ADVERTISE:           return "Advertise";
	case DHCPV6_REQUEST:             return "Request";
	case DHCPV6_CONFIRM:             return "Confirm";
	case DHCPV6_RENEW:               return "Renew";
	case DHCPV6_REBIND:              return "Rebind";
	case DHCPV6_REPLY:               return "Reply";
	case DHCPV6_RELEASE:             return "Release";
	case DHCPV6_DECLINE:             return "Decline";
	case DHCPV6_RECONFIGURE:         return "Reconfigure";
	case DHCPV6_INFORMATION_REQUEST: return "Information-Request";
	case DHCPV6_RELAY_FORWARD:       return "Relay-Forward";
	case DHCPV6_RELAY_REPLY:         return "Relay-Reply";
	default:                          return "Unknown";
	}
}

int validate_nd_options(struct ndp_msg *msg)
{
	const uint8_t *ptr = ndp_msg_payload_opts(msg);
	size_t remaining = ndp_msg_payload_opts_len(msg);

	while (remaining > 0) {
		const struct nd_option_header_wire *header;
		size_t opt_len;

		if (remaining < sizeof(*header))
			return -1;

		header = (const struct nd_option_header_wire *)ptr;
		if (header->length_units == 0)
			return -1;

		opt_len = (size_t)header->length_units * NDP_OPTION_LEN_UNIT_OCTETS;
		if (opt_len > remaining)
			return -1;

		ptr += opt_len;
		remaining -= opt_len;
	}

	return 0;
}

static uint32_t checksum_fold(uint32_t sum)
{
	const unsigned int word_bits = sizeof(uint16_t) * CHAR_BIT;

	while (sum >> word_bits)
		sum = (sum & UINT16_MAX) + (sum >> word_bits);

	return sum;
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *buf, size_t len)
{
	while (len >= sizeof(uint16_t)) {
		sum += read_be16(buf);
		buf += sizeof(uint16_t);
		len -= sizeof(uint16_t);
	}

	if (len != 0)
		sum += (uint32_t)buf[0] << CHAR_BIT;

	return checksum_fold(sum);
}

/*
 * libnetfilter_queue 1.0.5 has public UDP checksum helpers but no public
 * ICMPv6 checksum helper. Keep this one small checksum routine for RA only.
 */
uint16_t icmpv6_checksum(const struct ip6_hdr *ip6h,
				const uint8_t *icmp, size_t icmp_len)
{
	struct ipv6_pseudo_header pseudo = {
		.source = ip6h->ip6_src,
		.destination = ip6h->ip6_dst,
		.payload_length = htonl((uint32_t)icmp_len),
		.reserved = { 0 },
		.next_header = IPPROTO_ICMPV6,
	};
	uint32_t sum = 0;

	sum = checksum_add(sum, (const uint8_t *)&pseudo, sizeof(pseudo));
	sum = checksum_add(sum, icmp, icmp_len);

	return (uint16_t)~checksum_fold(sum);
}
