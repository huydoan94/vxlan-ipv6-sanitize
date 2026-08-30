#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_icmp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <ndp.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define QUEUE_NUM 100U
#define QUEUE_MAXLEN 1024U
#define COPY_RANGE UINT16_MAX
#define POLL_TIMEOUT_MS 1000
#define NFQ_NETLINK_HEADROOM 4096U
#define NFQ_RECV_BUFSIZE ((size_t)COPY_RANGE + NFQ_NETLINK_HEADROOM)

#define NDP_OPTION_LEN_UNIT_OCTETS 8U
#define ND_ROUTER_ADVERT_REQUIRED_HOP_LIMIT UINT8_MAX
#define ND_ROUTER_ADVERT_CODE 0U
#define RA_NEUTRAL_ROUTER_LIFETIME 0U

#define DHCPV6_SERVER_PORT 547U
#define DHCPV6_CLIENT_PORT 546U
#define DHCPV6_OPT_CLIENTID 1U
#define DHCPV6_OPT_DNS_SERVERS 23U
#define DHCPV6_TRANSACTION_ID_LEN 3U

#define DUID_LLT 1U
#define DUID_LL 3U
#define HWTYPE_ETHERNET 1U

#define IPV6_ULA_PREFIX_MASK 0xfeU
#define IPV6_ULA_PREFIX_VALUE 0xfcU
#define IPV6_PSEUDO_RESERVED_LEN 3U

#define ADDR_LIST_BUFSIZE 512U
#define CLIENT_ID_BUFSIZE 384U
#define DETAIL_BUFSIZE 1536U
#define ERROR_BUFSIZE 256U
#define ENDPOINT_BUFSIZE 256U
#define SYSFS_LINK_BUFSIZE 256U
#define MAC_TEXT_BUFSIZE (ETH_ALEN * 3U)
#define DESTINATION_TEXT_BUFSIZE \
	(INET6_ADDRSTRLEN + sizeof("(all-dhcp-agents)"))

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

struct vlan_tag_wire {
	uint16_t tci;
	uint16_t encapsulated_proto;
} __attribute__((packed));

struct nd_option_header_wire {
	uint8_t type;
	uint8_t length_units;
} __attribute__((packed));

struct rdnss_option_wire {
	uint8_t type;
	uint8_t length_units;
	uint16_t reserved;
	uint32_t lifetime;
	uint8_t addresses[];
} __attribute__((packed));

struct dhcpv6_direct_header_wire {
	uint8_t message_type;
	uint8_t transaction_id[DHCPV6_TRANSACTION_ID_LEN];
} __attribute__((packed));

struct dhcpv6_option_header_wire {
	uint16_t code;
	uint16_t length;
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

struct app_ctx {
	bool verbose;
	struct ndp_msg *ra_msg;
};

struct addr_list {
	char buf[ADDR_LIST_BUFSIZE];
	size_t len;
	bool first;
	bool truncated;
};

static volatile sig_atomic_t running = 1;

static uint16_t read_be16(const uint8_t *p)
{
	uint16_t network_value;

	memcpy(&network_value, p, sizeof(network_value));
	return ntohs(network_value);
}

static uint32_t read_be24(const uint8_t *p)
{
	uint32_t value = 0;
	size_t i;

	for (i = 0; i < DHCPV6_TRANSACTION_ID_LEN; i++)
		value = (value << CHAR_BIT) | p[i];

	return value;
}

static void write_be16(uint8_t *p, uint16_t value)
{
	uint16_t network_value = htons(value);

	memcpy(p, &network_value, sizeof(network_value));
}

__attribute__((format(printf, 2, 3)))
static void log_info(const struct app_ctx *ctx, const char *fmt, ...)
{
	va_list args;

	if (!ctx->verbose)
		return;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
	fputc('\n', stdout);
	fflush(stdout);
}

__attribute__((format(printf, 1, 2)))
static void log_error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fputc('\n', stderr);
	fflush(stderr);
}

__attribute__((format(printf, 3, 4)))
static void set_error(char *buf, size_t len, const char *fmt, ...)
{
	va_list args;

	if (len == 0)
		return;

	va_start(args, fmt);
	vsnprintf(buf, len, fmt, args);
	va_end(args);
}

static void handle_signal(int sig)
{
	(void)sig;
	running = 0;
}

static int install_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGINT, &sa, NULL) < 0)
		return -1;
	if (sigaction(SIGTERM, &sa, NULL) < 0)
		return -1;

	return 0;
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

static int resolve_local_dns(uint32_t indev, uint32_t physindev,
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

static int locate_ipv6(const uint8_t *packet, size_t packet_len,
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

static void format_endpoints(const uint8_t *packet, size_t packet_len,
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

static void addr_list_init(struct addr_list *list)
{
	snprintf(list->buf, sizeof(list->buf), "[");
	list->len = strlen(list->buf);
	list->first = true;
	list->truncated = false;
}

static void addr_list_append(struct addr_list *list, const struct in6_addr *addr)
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

static const char *addr_list_finish(struct addr_list *list)
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

static void format_hex(const uint8_t *data, size_t data_len,
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

static void duid_ethernet_mac(const uint8_t *duid, size_t len,
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

static const char *dhcpv6_msg_name(uint8_t type)
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

static int validate_nd_options(struct ndp_msg *msg)
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
static uint16_t icmpv6_checksum(const struct ip6_hdr *ip6h,
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

/*
 * Return 1 when changed, 0 when this is not a supported RA or no change is
 * required, and -1 for a malformed RA that must be accepted unchanged.
 */
static int sanitize_ra(struct app_ctx *ctx, struct pkt_buff *pktb,
		       struct ip6_hdr *ip6h, const struct in6_addr *local_dns,
		       const char *endpoints,
		       char *detail, size_t detail_len,
		       char *error, size_t error_len)
{
	struct icmphdr *generic_icmp;
	struct ndp_msgra *ra;
	uint8_t *icmp_bytes;
	size_t icmp_offset;
	size_t icmp_len;
	uint16_t original_lifetime;
	unsigned int rewritten = 0;
	bool changed = false;
	struct addr_list original_rdnss;
	struct addr_list modified_rdnss;
	int opt_offset;

	if (!nfq_ip6_set_transport_header(pktb, ip6h, IPPROTO_ICMPV6))
		return 0;

	generic_icmp = nfq_icmp_get_hdr(pktb);
	if (generic_icmp == NULL)
		return 0;

	icmp_bytes = (uint8_t *)generic_icmp;
	icmp_offset = (size_t)(icmp_bytes - (uint8_t *)pktb_data(pktb));
	if (icmp_offset > pktb_len(pktb))
		return 0;
	icmp_len = pktb_len(pktb) - icmp_offset;

	if (icmp_len < sizeof(struct nd_router_advert)) {
		set_error(error, error_len, "truncated Router Advertisement");
		return -1;
	}

	if (generic_icmp->type != ND_ROUTER_ADVERT ||
	    generic_icmp->code != ND_ROUTER_ADVERT_CODE)
		return 0;

	if (ip6h->ip6_hlim != ND_ROUTER_ADVERT_REQUIRED_HOP_LIMIT) {
		set_error(error, error_len,
			  "RA hop limit %u is not %u", ip6h->ip6_hlim,
			  ND_ROUTER_ADVERT_REQUIRED_HOP_LIMIT);
		return -1;
	}

	if (icmp_len > ndp_msg_payload_maxlen(ctx->ra_msg)) {
		set_error(error, error_len,
			  "RA length %zu exceeds libndp buffer %zu",
			  icmp_len, ndp_msg_payload_maxlen(ctx->ra_msg));
		return -1;
	}

	/*
	 * Seed a reusable libndp RA object with an exact private copy of the
	 * received ICMPv6 message. libndp then owns typed RA lifetime access and
	 * RDNSS option discovery; no RA is serialized or reconstructed.
	 */
	memcpy(ndp_msg_payload(ctx->ra_msg), icmp_bytes, icmp_len);
	ndp_msg_payload_len_set(ctx->ra_msg, icmp_len);

	if (validate_nd_options(ctx->ra_msg) < 0) {
		set_error(error, error_len, "malformed RA option stream");
		return -1;
	}

	ra = ndp_msgra(ctx->ra_msg);
	if (ra == NULL) {
		set_error(error, error_len, "libndp did not recognize Router Advertisement");
		return -1;
	}

	original_lifetime = ndp_msgra_router_lifetime(ra);
	if (original_lifetime != RA_NEUTRAL_ROUTER_LIFETIME) {
		ndp_msgra_router_lifetime_set(ra, RA_NEUTRAL_ROUTER_LIFETIME);
		changed = true;
	}

	addr_list_init(&original_rdnss);
	addr_list_init(&modified_rdnss);

	ndp_msg_opt_for_each_offset(opt_offset, ctx->ra_msg, NDP_MSG_OPT_RDNSS) {
		uint8_t *opts = ndp_msg_payload_opts(ctx->ra_msg);
		size_t opts_len = ndp_msg_payload_opts_len(ctx->ra_msg);
		struct nd_option_header_wire *header;
		uint8_t *opt;
		size_t opt_len;
		const size_t fixed_len = offsetof(struct rdnss_option_wire, addresses);
		const size_t minimum_len = fixed_len + sizeof(struct in6_addr);
		int addr_index;
		struct in6_addr *addr;

		if (opt_offset < 0 ||
		    (size_t)opt_offset + sizeof(*header) > opts_len) {
			set_error(error, error_len, "invalid libndp RDNSS offset");
			return -1;
		}

		opt = opts + opt_offset;
		header = (struct nd_option_header_wire *)opt;
		opt_len = (size_t)header->length_units * NDP_OPTION_LEN_UNIT_OCTETS;

		/* RFC 8106: fixed fields followed by one or more IPv6 addresses. */
		if (opt_len < minimum_len ||
		    (size_t)opt_offset + opt_len > opts_len ||
		    (opt_len - fixed_len) % sizeof(struct in6_addr) != 0) {
			set_error(error, error_len,
				  "invalid RDNSS option length %zu", opt_len);
			return -1;
		}

		ndp_msg_opt_rdnss_for_each_addr(addr, addr_index,
						ctx->ra_msg, opt_offset) {
			uint8_t *wire_addr = opt + fixed_len +
				(size_t)addr_index * sizeof(struct in6_addr);

			addr_list_append(&original_rdnss, addr);

			if (memcmp(wire_addr, local_dns, sizeof(*local_dns)) != 0) {
				memcpy(wire_addr, local_dns, sizeof(*local_dns));
				rewritten++;
				changed = true;
			}

			addr_list_append(&modified_rdnss, local_dns);
		}
	}

	if (!changed)
		return 0;

	/* Copy the exact libndp private message back, then update only checksum. */
	memcpy(icmp_bytes, ndp_msg_payload(ctx->ra_msg), icmp_len);
	/* Recalculate the checksum after the in-place RA modifications. */
	write_be16(icmp_bytes + offsetof(struct icmp6_hdr, icmp6_cksum), 0);
	write_be16(icmp_bytes + offsetof(struct icmp6_hdr, icmp6_cksum),
		   icmpv6_checksum(ip6h, icmp_bytes, icmp_len));

	snprintf(detail, detail_len,
		 "type=RA %s router-lifetime=%u->%u rdnss=%s->%s rdnss-rewritten=%u",
		 endpoints, original_lifetime, RA_NEUTRAL_ROUTER_LIFETIME,
		 addr_list_finish(&original_rdnss),
		 addr_list_finish(&modified_rdnss), rewritten);

	return 1;
}

/*
 * Return 1 when changed, 0 when this is not direct DHCPv6 server->client or
 * no DNS change is required, and -1 for malformed DHCPv6.
 */
static int sanitize_dhcpv6(struct pkt_buff *pktb, struct ip6_hdr *ip6h,
			   const struct in6_addr *local_dns,
			   const char *endpoints,
			   char *detail, size_t detail_len,
			   char *error, size_t error_len)
{
	struct udphdr *udp;
	uint8_t *dhcp;
	size_t available_udp_payload;
	size_t dhcp_len;
	size_t offset;
	uint16_t udp_len;
	uint8_t msg_type;
	uint32_t xid;
	unsigned int dns_options = 0;
	unsigned int rewritten = 0;
	char client_id[CLIENT_ID_BUFSIZE] = "";
	char client_mac[MAC_TEXT_BUFSIZE] = "";
	struct addr_list original_dns;
	struct addr_list modified_dns;

	if (!nfq_ip6_set_transport_header(pktb, ip6h, IPPROTO_UDP))
		return 0;

	udp = nfq_udp_get_hdr(pktb);
	if (udp == NULL)
		return 0;

	if (ntohs(udp->source) != DHCPV6_SERVER_PORT ||
	    ntohs(udp->dest) != DHCPV6_CLIENT_PORT)
		return 0;

	available_udp_payload = nfq_udp_get_payload_len(udp, pktb);
	udp_len = ntohs(udp->len);
	if (udp_len < sizeof(*udp) ||
	    (size_t)udp_len - sizeof(*udp) > available_udp_payload) {
		set_error(error, error_len, "invalid UDP length %u", udp_len);
		return -1;
	}

	dhcp = nfq_udp_get_payload(udp, pktb);
	if (dhcp == NULL) {
		set_error(error, error_len, "DHCPv6 UDP payload unavailable");
		return -1;
	}
	dhcp_len = (size_t)udp_len - sizeof(*udp);

	if (dhcp_len < sizeof(struct dhcpv6_direct_header_wire)) {
		set_error(error, error_len, "truncated DHCPv6 direct-message header");
		return -1;
	}

	msg_type = dhcp[offsetof(struct dhcpv6_direct_header_wire, message_type)];
	if (msg_type == DHCPV6_RELAY_FORWARD || msg_type == DHCPV6_RELAY_REPLY)
		return 0;

	xid = read_be24(dhcp +
		offsetof(struct dhcpv6_direct_header_wire, transaction_id));

	addr_list_init(&original_dns);
	addr_list_init(&modified_dns);

	/*
	 * DHCPv6 has no lightweight parser library in the OpenWrt base/packages
	 * set. Keep one bounds-checked top-level TLV pass. Nested IA_NA/IAADDR and
	 * all unknown options remain opaque and byte-for-byte untouched.
	 */
	offset = sizeof(struct dhcpv6_direct_header_wire);
	while (offset < dhcp_len) {
		uint16_t code;
		uint16_t opt_len;
		size_t data_offset;
		size_t i;

		if (dhcp_len - offset < sizeof(struct dhcpv6_option_header_wire)) {
			set_error(error, error_len, "truncated DHCPv6 option header");
			return -1;
		}

		code = read_be16(dhcp + offset +
			offsetof(struct dhcpv6_option_header_wire, code));
		opt_len = read_be16(dhcp + offset +
			offsetof(struct dhcpv6_option_header_wire, length));
		data_offset = offset + sizeof(struct dhcpv6_option_header_wire);

		if ((size_t)opt_len > dhcp_len - data_offset) {
			set_error(error, error_len,
				  "DHCPv6 option %u overruns packet", code);
			return -1;
		}

		if (code == DHCPV6_OPT_CLIENTID && client_id[0] == '\0') {
			format_hex(dhcp + data_offset, opt_len,
				   client_id, sizeof(client_id));
			duid_ethernet_mac(dhcp + data_offset, opt_len,
					  client_mac, sizeof(client_mac));
		}

		if (code == DHCPV6_OPT_DNS_SERVERS) {
			dns_options++;
			if (opt_len == 0 || opt_len % sizeof(struct in6_addr) != 0) {
				set_error(error, error_len,
					  "invalid DHCPv6 DNS option length %u", opt_len);
				return -1;
			}

			for (i = 0; i < opt_len; i += sizeof(struct in6_addr)) {
				struct in6_addr old_addr;

				memcpy(&old_addr, dhcp + data_offset + i, sizeof(old_addr));
				addr_list_append(&original_dns, &old_addr);
				if (memcmp(&old_addr, local_dns, sizeof(*local_dns)) != 0)
					rewritten++;
				addr_list_append(&modified_dns, local_dns);
			}
		}

		offset = data_offset + opt_len;
	}

	if (rewritten == 0)
		return 0;

	/*
	 * Second pass: use libnetfilter_queue's UDP/IPv6 mangler for every DNS
	 * address. It updates packet lengths (unchanged here) and recalculates the
	 * mandatory UDP/IPv6 checksum after each replacement.
	 */
	offset = sizeof(struct dhcpv6_direct_header_wire);
	while (offset < dhcp_len) {
		uint16_t code = read_be16(dhcp + offset +
			offsetof(struct dhcpv6_option_header_wire, code));
		uint16_t opt_len = read_be16(dhcp + offset +
			offsetof(struct dhcpv6_option_header_wire, length));
		size_t data_offset = offset + sizeof(struct dhcpv6_option_header_wire);
		size_t i;

		if (code == DHCPV6_OPT_DNS_SERVERS) {
			for (i = 0; i < opt_len; i += sizeof(struct in6_addr)) {
				if (memcmp(dhcp + data_offset + i, local_dns,
					   sizeof(*local_dns)) == 0)
					continue;

				if (!nfq_udp_mangle_ipv6(pktb,
							(unsigned int)(data_offset + i),
							(unsigned int)sizeof(*local_dns),
							(const char *)local_dns,
							(unsigned int)sizeof(*local_dns))) {
					set_error(error, error_len,
						  "libnetfilter_queue failed to mangle DHCPv6 DNS");
					return -1;
				}
			}
		}

		offset = data_offset + opt_len;
	}

	/* A computed UDP checksum of zero is transmitted as all ones. */
	udp = nfq_udp_get_hdr(pktb);
	if (udp == NULL) {
		set_error(error, error_len, "UDP header unavailable after mangling");
		return -1;
	}
	if (udp->check == 0)
		udp->check = htons(UINT16_MAX);

	snprintf(detail, detail_len,
		 "type=DHCPv6-%s %s xid=0x%0*x client-id=%s client-mac=%s "
		 "dns=%s->%s dns-options=%u dns-rewritten=%u",
		 dhcpv6_msg_name(msg_type), endpoints,
		 (int)(DHCPV6_TRANSACTION_ID_LEN * 2U), xid,
		 client_id[0] ? client_id : "-",
		 client_mac[0] ? client_mac : "-",
		 addr_list_finish(&original_dns),
		 addr_list_finish(&modified_dns),
		 dns_options, rewritten);

	return 1;
}

static int accept_unchanged(struct nfq_q_handle *qh, uint32_t id)
{
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static int verdict_with_modified_l3(struct nfq_q_handle *qh, uint32_t id,
				    uint8_t *original, size_t original_len,
				    size_t ipv6_offset, size_t original_ipv6_len,
				    struct pkt_buff *pktb)
{
	size_t new_ipv6_len = pktb_len(pktb);

	if (new_ipv6_len != original_ipv6_len)
		return -1; /* Current policy only performs same-length replacements. */
	if (ipv6_offset > original_len ||
	    original_ipv6_len > original_len - ipv6_offset)
		return -1;

	/*
	 * All parsing and rewriting was performed in pktb's private copy. Only
	 * after it has succeeded do we update the NFQUEUE receive payload.
	 * nfq_set_verdict() consumes the replacement buffer synchronously while
	 * sending its netlink verdict, so no second full-frame allocation is
	 * required. If the verdict send itself fails, a later plain NF_ACCEPT
	 * still accepts the kernel's original queued packet unchanged.
	 */
	memcpy(original + ipv6_offset, pktb_data(pktb), new_ipv6_len);

	return nfq_set_verdict(qh, id, NF_ACCEPT,
			       (uint32_t)original_len, original);
}

static int packet_cb(struct nfq_q_handle *qh,
		     struct nfgenmsg *nfmsg,
		     struct nfq_data *nfa,
		     void *data)
{
	struct app_ctx *ctx = data;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *payload = NULL;
	struct pkt_buff *pktb = NULL;
	struct ip6_hdr *ip6h;
	struct in6_addr local_dns;
	char dns_ifname[IF_NAMESIZE] = "";
	char dns_buf[INET6_ADDRSTRLEN];
	char endpoints[ENDPOINT_BUFSIZE];
	char detail[DETAIL_BUFSIZE] = "";
	char error[ERROR_BUFSIZE] = "";
	uint32_t id = 0;
	uint32_t indev;
	uint32_t physindev;
	size_t ipv6_offset;
	size_t ipv6_len;
	int payload_len;
	int changed;
	int verdict;

	(void)nfmsg;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph != NULL)
		id = ntohl(ph->packet_id);

	payload_len = nfq_get_payload(nfa, &payload);
	if (payload_len <= 0 || payload == NULL) {
		log_error("id=%u: NFQUEUE payload unavailable; ACCEPT unchanged", id);
		return accept_unchanged(qh, id);
	}

	if (locate_ipv6(payload, (size_t)payload_len,
			&ipv6_offset, &ipv6_len) < 0) {
		log_error("id=%u: could not locate a complete IPv6 packet; ACCEPT unchanged",
			  id);
		return accept_unchanged(qh, id);
	}

	pktb = pktb_alloc(AF_INET6, payload + ipv6_offset, ipv6_len, 0);
	if (pktb == NULL) {
		log_error("id=%u: pktb_alloc() failed; ACCEPT unchanged", id);
		return accept_unchanged(qh, id);
	}

	ip6h = nfq_ip6_get_hdr(pktb);
	if (ip6h == NULL) {
		log_error("id=%u: libnetfilter_queue rejected IPv6 header; ACCEPT unchanged",
			  id);
		pktb_free(pktb);
		return accept_unchanged(qh, id);
	}

	format_endpoints(payload, (size_t)payload_len,
			 ipv6_offset, ip6h, endpoints, sizeof(endpoints));

	indev = nfq_get_indev(nfa);
	physindev = nfq_get_physindev(nfa);
	if (resolve_local_dns(indev, physindev, &local_dns,
			      dns_ifname, sizeof(dns_ifname)) < 0) {
		log_error("id=%u: no ULA found on ingress interface or bridge master; "
			  "ACCEPT unchanged", id);
		pktb_free(pktb);
		return accept_unchanged(qh, id);
	}

	if (inet_ntop(AF_INET6, &local_dns, dns_buf, sizeof(dns_buf)) == NULL)
		snprintf(dns_buf, sizeof(dns_buf), "?");

	changed = sanitize_ra(ctx, pktb, ip6h, &local_dns,
			      endpoints, detail, sizeof(detail),
			      error, sizeof(error));
	if (changed == 0) {
		error[0] = '\0';
		changed = sanitize_dhcpv6(pktb, ip6h, &local_dns,
					  endpoints, detail, sizeof(detail),
					  error, sizeof(error));
	}

	if (changed < 0) {
		log_error("id=%u: %s; ACCEPT unchanged",
			  id, error[0] ? error : "packet sanitizer failed");
		pktb_free(pktb);
		return accept_unchanged(qh, id);
	}

	if (changed == 0) {
		pktb_free(pktb);
		return accept_unchanged(qh, id);
	}

	log_info(ctx, "id=%u local-dns=%s(%s) %s",
		 id, dns_buf, dns_ifname, detail);

	verdict = verdict_with_modified_l3(qh, id,
				   payload, (size_t)payload_len,
				   ipv6_offset, ipv6_len, pktb);
	if (verdict < 0) {
		log_error("id=%u: could not construct modified verdict; ACCEPT unchanged",
			  id);
		pktb_free(pktb);
		return accept_unchanged(qh, id);
	}

	pktb_free(pktb);
	return verdict;
}

static void usage(const char *prog)
{
	fprintf(stdout, "Usage: %s [-v]\n", prog);
}

int main(int argc, char **argv)
{
	struct app_ctx ctx = { 0 };
	struct nfq_handle *h = NULL;
	struct nfq_q_handle *qh = NULL;
	struct pollfd pfd;
	int fd;
	int rv;
	int opt;
	int exit_status = EXIT_SUCCESS;
	ssize_t recv_len;
	char buf[NFQ_RECV_BUFSIZE] __attribute__((aligned));

	while ((opt = getopt(argc, argv, "vh")) != -1) {
		switch (opt) {
		case 'v':
			ctx.verbose = true;
			break;
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	/* procd captures these streams; keep every message immediately visible. */
	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if (ndp_msg_new(&ctx.ra_msg, NDP_MSG_RA) < 0) {
		log_error("ndp_msg_new(NDP_MSG_RA) failed");
		return EXIT_FAILURE;
	}

	if (install_signal_handlers() < 0) {
		log_error("failed to install signal handlers: %s", strerror(errno));
		exit_status = EXIT_FAILURE;
		goto out_ndp;
	}

	h = nfq_open();
	if (h == NULL) {
		log_error("nfq_open() failed");
		exit_status = EXIT_FAILURE;
		goto out_ndp;
	}

	qh = nfq_create_queue(h, QUEUE_NUM, &packet_cb, &ctx);
	if (qh == NULL) {
		log_error("nfq_create_queue(%u) failed", QUEUE_NUM);
		exit_status = EXIT_FAILURE;
		goto out_nfq;
	}

	/*
	 * nft's `queue ... bypass` only handles the no-listener case.  A full
	 * kernel NFQUEUE is dropped by default, so explicitly enable the kernel
	 * fail-open flag as well.  OpenWrt 25.12 kernels support this flag.
	 */
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN,
				NFQA_CFG_F_FAIL_OPEN) < 0) {
		log_error("nfq_set_queue_flags(FAIL_OPEN) failed: %s",
			  strerror(errno));
		exit_status = EXIT_FAILURE;
		goto out_queue;
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, COPY_RANGE) < 0) {
		log_error("nfq_set_mode() failed");
		exit_status = EXIT_FAILURE;
		goto out_queue;
	}

	if (nfq_set_queue_maxlen(qh, QUEUE_MAXLEN) < 0)
		log_error("nfq_set_queue_maxlen(%u) failed", QUEUE_MAXLEN);

	fd = nfq_fd(h);
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	log_info(&ctx, "vxlan-ipv6-sanitize listening on NFQUEUE %u", QUEUE_NUM);

	while (running) {
		rv = poll(&pfd, 1, POLL_TIMEOUT_MS);
		if (rv == 0)
			continue;
		if (rv < 0) {
			if (errno == EINTR)
				continue;
			log_error("poll() failed: %s", strerror(errno));
			exit_status = EXIT_FAILURE;
			break;
		}

		if (!(pfd.revents & POLLIN)) {
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				log_error("NFQUEUE socket poll error: revents=0x%x",
					  pfd.revents);
				exit_status = EXIT_FAILURE;
				break;
			}
			continue;
		}

		recv_len = recv(fd, buf, sizeof(buf), 0);
		if (recv_len >= 0) {
			if (nfq_handle_packet(h, buf, (int)recv_len) < 0) {
				log_error("nfq_handle_packet() failed");
				exit_status = EXIT_FAILURE;
				break;
			}
			continue;
		}

		if (errno == EINTR)
			continue;
		if (errno == ENOBUFS) {
			log_error("NFQUEUE receive buffer overflow");
			continue;
		}

		log_error("recv() failed: %s", strerror(errno));
		exit_status = EXIT_FAILURE;
		break;
	}

	log_info(&ctx, "stopping");

out_queue:
	if (qh != NULL)
		nfq_destroy_queue(qh);
out_nfq:
	if (h != NULL)
		nfq_close(h);
out_ndp:
	ndp_msg_destroy(ctx.ra_msg);
	return exit_status;
}
