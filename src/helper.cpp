#include "helper.h"

#include <array>
#include <climits>
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <vector>
#include <unistd.h>

#include <tins/constants.h>
#include <tins/endianness.h>
#include <tins/ipv6_address.h>
#include <tins/network_interface.h>
#include <tins/utils/checksum_utils.h>

constexpr unsigned int IPV6_WIRE_VERSION = 6U;
constexpr unsigned int IPV6_VERSION_FIELD_BITS = 4U;
constexpr uint8_t IPV6_ULA_PREFIX_MASK = 0xfeU;
constexpr uint8_t IPV6_ULA_PREFIX_VALUE = 0xfcU;
constexpr size_t SYSFS_LINK_BUFSIZE = 256U;

uint16_t read_be16(const uint8_t *p)
{
	uint16_t network_value;

	std::memcpy(&network_value, p, sizeof(network_value));
	return Tins::Endian::be_to_host(network_value);
}

static bool is_ula(const Tins::IPv6Address& addr)
{
	return (addr.begin()[0] & IPV6_ULA_PREFIX_MASK) == IPV6_ULA_PREFIX_VALUE;
}

static bool get_bridge_master(const std::string& ifname, std::string& master)
{
	std::array<char, SYSFS_LINK_BUFSIZE> path;
	std::array<char, SYSFS_LINK_BUFSIZE> target;
	const char *base;
	ssize_t n;

	if (std::snprintf(path.data(), path.size(), "/sys/class/net/%s/master",
	                  ifname.c_str()) >= static_cast<int>(path.size()))
		return false;

	n = readlink(path.data(), target.data(), target.size() - 1U);
	if (n < 0)
		return false;

	target[static_cast<size_t>(n)] = '\0';
	base = std::strrchr(target.data(), '/');
	master = base != nullptr ? base + 1 : target.data();

	return !master.empty();
}

static bool find_ula_on_interface(const std::string& ifname,
                                  struct in6_addr *result)
{
	const std::vector<Tins::NetworkInterface::IPv6Prefix> addresses = Tins::NetworkInterface(ifname).ipv6_addresses();

	for (const Tins::NetworkInterface::IPv6Prefix& prefix : addresses) {
		if (!is_ula(prefix.address))
			continue;

		prefix.address.copy(result->s6_addr);
		return true;
	}

	return false;
}

int resolve_local_dns(uint32_t indev, uint32_t physindev,
                      struct in6_addr *dns,
                      char *source_ifname, size_t source_ifname_len)
{
	const std::array<uint32_t, 2> candidates = {{ indev, physindev }};

	for (size_t i = 0; i < candidates.size(); ++i) {
		const uint32_t ifindex = candidates[i];

		if (ifindex == 0)
			continue;
		if (i > 0 && candidates[i] == candidates[0])
			continue;

		try {
			std::string ifname = Tins::NetworkInterface::from_index(ifindex).name();
			std::string resolved_ifname = ifname;
			std::string master;

			if (!find_ula_on_interface(ifname, dns)) {
				if (!get_bridge_master(ifname, master) ||
				    !find_ula_on_interface(master, dns))
					continue;
				resolved_ifname = master;
			}

			if (source_ifname != nullptr && source_ifname_len != 0)
				std::snprintf(source_ifname, source_ifname_len, "%s",
				              resolved_ifname.c_str());
			return 0;
		}
		catch (const std::exception&) {
			continue;
		}
	}

	return -1;
}

static bool has_ipv6_version(const uint8_t *packet)
{
	const unsigned int version_shift = CHAR_BIT - IPV6_VERSION_FIELD_BITS;

	return (packet[0] >> version_shift) == IPV6_WIRE_VERSION;
}

enum ipv6_packet_result
parse_nfqueue_ipv6_payload(uint8_t *payload, size_t payload_len,
                           struct ipv6_packet_view *view)
{
	const size_t ipv6_payload_len_offset = offsetof(struct ip6_hdr, ip6_plen);
	uint16_t ipv6_payload_len;
	size_t ipv6_packet_len;

	if (payload == nullptr || view == nullptr || payload_len < sizeof(struct ip6_hdr) || !has_ipv6_version(payload))
		return IPV6_PACKET_PASSTHROUGH;

	ipv6_payload_len = read_be16(payload + ipv6_payload_len_offset);
	if (ipv6_payload_len == 0)
		return IPV6_PACKET_PASSTHROUGH;

	ipv6_packet_len = sizeof(struct ip6_hdr) + (size_t)ipv6_payload_len;
	if (ipv6_packet_len > payload_len)
		return IPV6_PACKET_TRUNCATED;

	view->data = payload;
	view->header = reinterpret_cast<struct ip6_hdr *>(payload);
	view->declared_len = ipv6_packet_len;
	view->captured_len = payload_len;
	view->declared_end = payload + ipv6_packet_len;
	view->captured_end = payload + payload_len;
	return IPV6_PACKET_OK;
}

int ipv6_packet_remove(struct ipv6_packet_view *packet,
                       uint8_t *remove_start, size_t remove_len)
{
	uint8_t *remove_end;
	uint16_t payload_len;

	if (packet == nullptr || remove_start == nullptr || remove_len == 0)
		return remove_len == 0 ? 0 : -1;
	if (remove_start < packet->data + sizeof(struct ip6_hdr) || remove_start > packet->declared_end)
		return -1;
	if (remove_len > (size_t)(packet->declared_end - remove_start))
		return -1;

	payload_len = Tins::Endian::be_to_host(packet->header->ip6_plen);
	if ((size_t)payload_len < remove_len)
		return -1;

	remove_end = remove_start + remove_len;
	std::memmove(remove_start, remove_end,
	             static_cast<size_t>(packet->captured_end - remove_end));

	packet->captured_len -= remove_len;
	packet->declared_len -= remove_len;
	packet->declared_end -= remove_len;
	packet->captured_end -= remove_len;
	packet->header->ip6_plen = Tins::Endian::host_to_be(
		static_cast<uint16_t>(static_cast<size_t>(payload_len) - remove_len));
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
		std::memmove(compactor->write, compactor->read, source_len);

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
		std::memmove(compactor->write, compactor->read, keep_len);

	compactor->read += source_len;
	compactor->write += keep_len;
}

size_t option_compactor_output_len(const struct option_compactor *compactor)
{
	return (size_t)(compactor->write - compactor->start);
}

static uint16_t ipv6_upperlayer_checksum(const struct ip6_hdr *ip6h,
                                         uint16_t protocol,
                                         const uint8_t *data, size_t data_len)
{
	uint32_t sum = Tins::Utils::pseudoheader_checksum(
		Tins::IPv6Address(ip6h->ip6_src.s6_addr),
		Tins::IPv6Address(ip6h->ip6_dst.s6_addr),
		static_cast<uint16_t>(data_len), protocol);

	sum += Tins::Utils::sum_range(data, data + data_len);
	while (sum >> 16U)
		sum = (sum & UINT16_MAX) + (sum >> 16U);

	return Tins::Endian::be_to_host(static_cast<uint16_t>(~sum));
}

uint16_t icmpv6_checksum(const struct ip6_hdr *ip6h,
                         const uint8_t *icmp, size_t icmp_len)
{
	return ipv6_upperlayer_checksum(ip6h, Tins::Constants::IP::PROTO_ICMPV6,
	                                icmp, icmp_len);
}

uint16_t udp_ipv6_checksum(const struct ip6_hdr *ip6h,
                           const uint8_t *udp, size_t udp_len)
{
	return ipv6_upperlayer_checksum(ip6h, Tins::Constants::IP::PROTO_UDP,
	                                udp, udp_len);
}
