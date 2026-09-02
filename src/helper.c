#define _GNU_SOURCE

#include "helper.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define IPV6_WIRE_VERSION 6U
#define IPV6_VERSION_FIELD_BITS 4U
#define IPV6_ULA_PREFIX_MASK 0xfeU
#define IPV6_ULA_PREFIX_VALUE 0xfcU
#define IPV6_PSEUDO_RESERVED_LEN 3U
#define SYSFS_LINK_BUFSIZE 256U

struct vlan_tag_wire {
	uint16_t tci;
	uint16_t encapsulated_proto;
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
		const char *resolved_ifname = NULL;

		if (ifindex == 0)
			continue;
		if (i > 0 && candidates[i] == candidates[0])
			continue;
		if (if_indextoname(ifindex, ifname) == NULL)
			continue;

		if (find_ula_on_interface(ifname, dns) == 0)
			resolved_ifname = ifname;
		else if (get_bridge_master(ifname, master, sizeof(master)) == 0 &&
		         find_ula_on_interface(master, dns) == 0)
			resolved_ifname = master;

		if (resolved_ifname == NULL)
			continue;

		if (source_ifname != NULL && source_ifname_len != 0)
			snprintf(source_ifname, source_ifname_len, "%s", resolved_ifname);
		return 0;
	}

	return -1;
}

/*
 * Parse the NFQUEUE bridge-family payload as one Ethernet frame containing a
 * complete IPv6 packet. VLAN tags are part of the L2 prefix; callers do not
 * need to calculate or carry an IPv6 offset.
 */
static bool has_ipv6_version(const uint8_t *packet)
{
	const unsigned int version_shift = CHAR_BIT - IPV6_VERSION_FIELD_BITS;

	return (packet[0] >> version_shift) == IPV6_WIRE_VERSION;
}

static bool is_vlan_ethertype(uint16_t ethertype)
{
	return ethertype == ETH_P_8021Q ||
	       ethertype == ETH_P_8021AD ||
	       ethertype == ETH_P_QINQ1;
}

int parse_bridge_ipv6_frame(uint8_t *frame, size_t frame_len,
                            struct bridge_packet_view *view)
{
	const size_t ethernet_proto_offset = offsetof(struct ethhdr, h_proto);
	const size_t vlan_proto_offset =
		offsetof(struct vlan_tag_wire, encapsulated_proto);
	const size_t ipv6_payload_len_offset = offsetof(struct ip6_hdr, ip6_plen);
	uint8_t *ipv6;
	uint8_t *frame_end;
	uint16_t ethertype;
	uint16_t payload_len;
	size_t l2_len;
	size_t ipv6_len;

	if (frame == NULL || view == NULL || frame_len < sizeof(struct ethhdr))
		return -1;

	frame_end = frame + frame_len;
	ethertype = read_be16(frame + ethernet_proto_offset);
	l2_len = sizeof(struct ethhdr);

	while (is_vlan_ethertype(ethertype)) {
		if (sizeof(struct vlan_tag_wire) > frame_len - l2_len)
			return -1;

		ethertype = read_be16(frame + l2_len + vlan_proto_offset);
		l2_len += sizeof(struct vlan_tag_wire);
	}

	if (ethertype != ETH_P_IPV6 || sizeof(struct ip6_hdr) > frame_len - l2_len)
		return -1;

	ipv6 = frame + l2_len;
	if (!has_ipv6_version(ipv6))
		return -1;

	payload_len = read_be16(ipv6 + ipv6_payload_len_offset);
	if (payload_len == 0)
		return -1; /* IPv6 jumbograms are outside this daemon's scope. */

	ipv6_len = sizeof(struct ip6_hdr) + (size_t)payload_len;
	if (ipv6_len > (size_t)(frame_end - ipv6))
		return -1;

	view->ethernet_frame = frame;
	view->ethernet_frame_len = frame_len;
	view->ipv6_packet = ipv6;
	view->ipv6_packet_len = ipv6_len;
	view->trailing_data = ipv6 + ipv6_len;
	view->trailing_data_len = (size_t)(frame_end - view->trailing_data);
	return 0;
}

void option_compactor_init(struct option_compactor *compactor, uint8_t *start)
{
	compactor->start = start;
	compactor->read = start;
	compactor->write = start;
}

void option_compactor_keep(struct option_compactor *compactor,
                           size_t source_len)
{
	if (compactor->write != compactor->read)
		memmove(compactor->write, compactor->read, source_len);

	compactor->read += source_len;
	compactor->write += source_len;
}

void option_compactor_skip(struct option_compactor *compactor,
                           size_t source_len)
{
	compactor->read += source_len;
}

void option_compactor_keep_prefix(struct option_compactor *compactor,
                                  size_t keep_len, size_t source_len)
{
	if (compactor->write != compactor->read)
		memmove(compactor->write, compactor->read, keep_len);

	compactor->read += source_len;
	compactor->write += keep_len;
}

size_t option_compactor_output_len(const struct option_compactor *compactor)
{
	return (size_t)(compactor->write - compactor->start);
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
