#include "logging.h"

#include "helper.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define DUID_LLT 1U
#define DUID_LL 3U
#define HWTYPE_ETHERNET 1U
#define DESTINATION_TEXT_BUFSIZE \
	(INET6_ADDRSTRLEN + sizeof("(all-dhcp-agents)"))

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

void log_info(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
	fputc('\n', stdout);
	fflush(stdout);
}

void log_error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fputc('\n', stderr);
	fflush(stderr);
}

void set_error(char *buf, size_t len, const char *fmt, ...)
{
	va_list args;

	if (len == 0)
		return;

	va_start(args, fmt);
	vsnprintf(buf, len, fmt, args);
	va_end(args);
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

static void format_ipv6(const struct in6_addr *addr, char *buf, size_t len)
{
	if (len == 0)
		return;

	if (inet_ntop(AF_INET6, addr, buf, (socklen_t)len) == NULL)
		snprintf(buf, len, "?");
}

static void format_destination(const struct in6_addr *addr,
                               char *buf, size_t len)
{
	static const char all_nodes[] = "ff02::1";
	static const char all_dhcp_agents[] = "ff02::1:2";
	char ip[INET6_ADDRSTRLEN];

	format_ipv6(addr, ip, sizeof(ip));

	if (ipv6_equals_literal(addr, all_nodes))
		snprintf(buf, len, "%s(all-nodes)", ip);
	else if (ipv6_equals_literal(addr, all_dhcp_agents))
		snprintf(buf, len, "%s(all-dhcp-agents)", ip);
	else
		snprintf(buf, len, "%s", ip);
}

void format_endpoints(const struct ip6_hdr *ip6h, char *buf, size_t len)
{
	char src[INET6_ADDRSTRLEN];
	char dst[DESTINATION_TEXT_BUFSIZE];

	format_ipv6(&ip6h->ip6_src, src, sizeof(src));
	format_destination(&ip6h->ip6_dst, dst, sizeof(dst));

	snprintf(buf, len, "from=%s to=%s", src, dst);
}

void format_local_dns_log(const struct in6_addr *dns, const char *ifname,
                          char *buf, size_t len)
{
	char ip[INET6_ADDRSTRLEN];

	format_ipv6(dns, ip, sizeof(ip));
	if (ifname != NULL && ifname[0] != '\0')
		snprintf(buf, len, "%s(%s)", ip, ifname);
	else
		snprintf(buf, len, "%s", ip);
}

void addr_list_init(struct addr_list *list)
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

void addr_list_append_wire_ipv6(struct addr_list *list,
                                const uint8_t *data, size_t data_len)
{
	const uint8_t *cursor = data;
	const uint8_t *end = data + data_len;

	while (cursor < end) {
		struct in6_addr addr;

		memcpy(&addr, cursor, sizeof(addr));
		addr_list_append(list, &addr);
		cursor += sizeof(addr);
	}
}

static const char *addr_list_finish(struct addr_list *list)
{
	const char *suffix = list->truncated ? ",...]" : "]";
	size_t suffix_len;

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

void format_dhcpv6_client_log_fields(const uint8_t *duid, size_t len,
                                     char *client_id, size_t client_id_len,
                                     char *client_mac, size_t client_mac_len)
{
	format_hex(duid, len, client_id, client_id_len);
	duid_ethernet_mac(duid, len, client_mac, client_mac_len);
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

static uint32_t read_transaction_id(const uint8_t *transaction_id)
{
	uint32_t value = 0;
	size_t i;

	for (i = 0; i < DHCPV6_TRANSACTION_ID_LEN; i++)
		value = (value << CHAR_BIT) | transaction_id[i];

	return value;
}

void format_ra_log_detail(char *detail, size_t detail_len,
                          const char *endpoints,
                          uint16_t original_lifetime,
                          uint16_t new_lifetime,
                          struct addr_list *original_rdnss,
                          unsigned int rdnss_options,
                          unsigned int rewritten,
                          unsigned int deduplicated,
                          unsigned int dnssl_removed)
{
	snprintf(detail, detail_len,
	         "type=RA %s router-lifetime=%u->%u rdnss=%s "
	         "rdnss-options=%u rdnss-rewritten=%u rdnss-deduplicated=%u "
	         "dnssl-removed=%u",
	         endpoints, original_lifetime, new_lifetime,
	         addr_list_finish(original_rdnss), rdnss_options, rewritten,
	         deduplicated, dnssl_removed);
}

void format_dhcpv6_log_detail(char *detail, size_t detail_len,
                              uint8_t msg_type,
                              const char *endpoints,
                              const uint8_t *transaction_id,
                              const char *client_id,
                              const char *client_mac,
                              struct addr_list *original_dns,
                              unsigned int dns_options,
                              unsigned int rewritten,
                              unsigned int deduplicated,
                              unsigned int domain_search_removed)
{
	uint32_t xid = read_transaction_id(transaction_id);

	snprintf(detail, detail_len,
	         "type=DHCPv6-%s %s xid=0x%0*x client-id=%s client-mac=%s "
	         "dns=%s dns-options=%u dns-rewritten=%u dns-deduplicated=%u "
	         "domain-search-removed=%u",
	         dhcpv6_msg_name(msg_type), endpoints,
	         (int)(DHCPV6_TRANSACTION_ID_LEN * 2U), xid,
	         client_id[0] ? client_id : "-",
	         client_mac[0] ? client_mac : "-",
	         addr_list_finish(original_dns),
	         dns_options, rewritten, deduplicated, domain_search_removed);
}
