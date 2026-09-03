#include "packet_parser.h"

#include <limits>

#include <tins/exceptions.h>
#include <tins/icmpv6.h>
#include <tins/ipv6.h>
#include <tins/pdu.h>
#include <tins/udp.h>

constexpr uint16_t DHCPV6_SERVER_PORT = 547U;
constexpr uint16_t DHCPV6_CLIENT_PORT = 546U;

namespace {

bool has_unsupported_extension(const Tins::IPv6& ipv6)
{
	return ipv6.search_header(Tins::IPv6::ROUTING) != nullptr ||
	       ipv6.search_header(Tins::IPv6::AUTHENTICATION) != nullptr ||
	       ipv6.search_header(Tins::IPv6::MOBILITY) != nullptr;
}

} // namespace

enum ipv6_transport_result
parse_ipv6_transport(uint8_t *packet, size_t packet_len,
                     struct ipv6_transport_view *transport)
{
	if (packet == nullptr || transport == nullptr || packet_len > std::numeric_limits<uint32_t>::max())
		return IPV6_TRANSPORT_MALFORMED;

	transport->packet_type = Tins::PDU::UNKNOWN;
	transport->header = nullptr;
	transport->len = 0;
	transport->fragmented = false;

	try {
		Tins::IPv6 ipv6(packet, static_cast<uint32_t>(packet_len));
		const Tins::PDU *inner;
		size_t transport_offset;

		if (ipv6.version() != 6)
			return IPV6_TRANSPORT_OTHER;

		/*
		 * Keep policy-sensitive headers out of the sanitizer. In particular,
		 * this also means we never depend on libtins' interpretation of an AH
		 * header when locating bytes that we may modify.
		 */
		if (has_unsupported_extension(ipv6))
			return IPV6_TRANSPORT_UNSUPPORTED;

		if (const Tins::IPv6::ext_header *fragment = ipv6.search_header(Tins::IPv6::FRAGMENT)) {
			const Tins::IPv6::fragment_header fragment_info = Tins::IPv6::fragment_header::from_extension_header(*fragment);

			if (fragment_info.fragment_offset != 0 || fragment_info.more_fragments) {
				transport->fragmented = true;
				return IPV6_TRANSPORT_FOUND;
			}

			/* libtins keeps atomic-fragment payloads raw; pass them unchanged. */
			return IPV6_TRANSPORT_UNSUPPORTED;
		}

		transport_offset = ipv6.header_size();
		if (transport_offset > packet_len)
			return IPV6_TRANSPORT_MALFORMED;

		inner = ipv6.inner_pdu();
		if (inner == nullptr)
			return IPV6_TRANSPORT_OTHER;

		switch (inner->pdu_type()) {
		case Tins::PDU::ICMPv6: {
			const Tins::ICMPv6 *icmpv6 = static_cast<const Tins::ICMPv6 *>(inner);

			if (icmpv6->type() == Tins::ICMPv6::ROUTER_ADVERT)
				transport->packet_type = Tins::PDU::ICMPv6;
			break;
		}
		case Tins::PDU::UDP: {
			const Tins::UDP *udp = static_cast<const Tins::UDP *>(inner);

			if (udp->sport() == DHCPV6_SERVER_PORT &&
			    udp->dport() == DHCPV6_CLIENT_PORT)
				transport->packet_type = Tins::PDU::DHCPv6;
			break;
		}
		case Tins::PDU::IPSEC_AH:
		case Tins::PDU::IPSEC_ESP:
			return IPV6_TRANSPORT_UNSUPPORTED;
		default:
			return IPV6_TRANSPORT_OTHER;
		}

		transport->header = packet + transport_offset;
		transport->len = packet_len - transport_offset;
		return IPV6_TRANSPORT_FOUND;
	}
	catch (const Tins::malformed_packet&) {
		return IPV6_TRANSPORT_MALFORMED;
	}
	catch (const Tins::invalid_ipv6_extension_header&) {
		return IPV6_TRANSPORT_MALFORMED;
	}
	catch (...) {
		/* Parser failures are fail-open at the caller. */
		return IPV6_TRANSPORT_MALFORMED;
	}
}
