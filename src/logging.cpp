#include "logging.h"

#include "helper.h"

#include <limits.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include <tins/dhcpv6.h>
#include <tins/hw_address.h>
#include <tins/ipv6_address.h>

constexpr size_t DESTINATION_TEXT_BUFSIZE = INET6_ADDRSTRLEN + sizeof("(all-dhcp-agents)");

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
	const std::string text = Tins::HWAddress<ETH_ALEN>(mac).to_string();

	if (len != 0)
		snprintf(buf, len, "%s", text.c_str());
}

static void format_ipv6(const struct in6_addr *addr, char *buf, size_t len)
{
	const std::string text = Tins::IPv6Address(addr->s6_addr).to_string();

	if (len != 0)
		snprintf(buf, len, "%s", text.c_str());
}

static void format_destination(const struct in6_addr *addr,
                               char *buf, size_t len)
{
	static const Tins::IPv6Address all_nodes("ff02::1");
	static const Tins::IPv6Address all_dhcp_agents("ff02::1:2");
	const Tins::IPv6Address destination(addr->s6_addr);
	const std::string ip = destination.to_string();

	if (destination == all_nodes)
		snprintf(buf, len, "%s(all-nodes)", ip.c_str());
	else if (destination == all_dhcp_agents)
		snprintf(buf, len, "%s(all-dhcp-agents)", ip.c_str());
	else
		snprintf(buf, len, "%s", ip.c_str());
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
	if (ifname != nullptr && ifname[0] != '\0')
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
	const std::string ip = Tins::IPv6Address(addr->s6_addr).to_string();
	char piece[INET6_ADDRSTRLEN + sizeof(",")];
	int n;

	if (list->truncated)
		return;

	n = snprintf(piece, sizeof(piece), "%s%s", list->first ? "" : ",",
	             ip.c_str());
	if (n < 0 || (size_t)n >= sizeof(piece) || list->len + (size_t)n + sizeof(",...]") > sizeof(list->buf)) {
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
		const size_t required = sizeof("ff") +
			(i + 1U < data_len ? sizeof(ellipsis) - 1U : 0U);

		if (required > buf_len - out)
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
	uint16_t duid_type;

	if (buf_len == 0)
		return;
	buf[0] = '\0';

	if (len < sizeof(uint16_t))
		return;

	duid_type = read_be16(duid);
	if (duid_type == Tins::DHCPv6::duid_llt::duid_id && len == sizeof(uint16_t) * 2U + sizeof(uint32_t) + ETH_ALEN) {
		const Tins::DHCPv6::duid_llt value = Tins::DHCPv6::duid_llt::from_bytes(
			duid + sizeof(uint16_t),
			static_cast<uint32_t>(len - sizeof(uint16_t)));

		if (value.hw_type == ARPHRD_ETHER)
			format_mac(value.lladdress.data(), buf, buf_len);
	} else if (duid_type == Tins::DHCPv6::duid_ll::duid_id && len == sizeof(uint16_t) * 2U + ETH_ALEN) {
		const Tins::DHCPv6::duid_ll value = Tins::DHCPv6::duid_ll::from_bytes(
			duid + sizeof(uint16_t),
			static_cast<uint32_t>(len - sizeof(uint16_t)));

		if (value.hw_type == ARPHRD_ETHER)
			format_mac(value.lladdress.data(), buf, buf_len);
	}
}

void format_dhcpv6_client_log_fields(const uint8_t *duid, size_t len,
                                     char *client_id, size_t client_id_len,
                                     char *client_mac, size_t client_mac_len)
{
	format_hex(duid, len, client_id, client_id_len);
	duid_ethernet_mac(duid, len, client_mac, client_mac_len);
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
                          unsigned int dnssl_removed,
                          unsigned int pvd_removed)
{
	snprintf(detail, detail_len,
	         "type=RA %s router-lifetime=%u->%u rdnss=%s "
	         "rdnss-options=%u rdnss-rewritten=%u rdnss-deduplicated=%u "
	         "dnssl-removed=%u pvd-removed=%u",
	         endpoints, original_lifetime, new_lifetime,
	         addr_list_finish(original_rdnss), rdnss_options, rewritten,
	         deduplicated, dnssl_removed, pvd_removed);
}

void format_dhcpv6_log_detail(char *detail, size_t detail_len,
                              const char *message_name,
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
	         message_name, endpoints,
	         (int)(DHCPV6_TRANSACTION_ID_LEN * 2U), xid,
	         client_id[0] ? client_id : "-",
	         client_mac[0] ? client_mac : "-",
	         addr_list_finish(original_dns),
	         dns_options, rewritten, deduplicated, domain_search_removed);
}
