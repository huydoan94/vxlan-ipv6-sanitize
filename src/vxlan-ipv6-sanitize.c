#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>

#include "helper.h"
#include "logging.h"

#define QUEUE_NUM 100U
#define QUEUE_MAXLEN 1024U
#define COPY_RANGE UINT16_MAX
#define POLL_TIMEOUT_MS 1000
#define NFQ_NETLINK_HEADROOM 4096U
#define NFQ_RECV_BUFSIZE ((size_t)COPY_RANGE + NFQ_NETLINK_HEADROOM)

#define ND_ROUTER_ADVERT_REQUIRED_HOP_LIMIT UINT8_MAX
#define ND_ROUTER_ADVERT_CODE 0U
#define RA_NEUTRAL_ROUTER_LIFETIME 0U
#define ND_OPTION_RDNSS 25U /* RFC 8106 Recursive DNS Server option. */
#define ND_OPTION_DNSSL 31U /* RFC 8106 DNS Search List option. */

#define DHCPV6_SERVER_PORT 547U
#define DHCPV6_CLIENT_PORT 546U
#define DHCPV6_OPT_CLIENTID 1U
#define DHCPV6_OPT_DNS_SERVERS 23U
#define DHCPV6_OPT_DOMAIN_LIST 24U

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

struct app_ctx {
	bool verbose;
};

enum packet_type {
	PACKET_OTHER = 0,
	PACKET_RA,
	PACKET_DHCPV6,
};

enum sanitize_result {
	SANITIZE_ERROR = -1,
	SANITIZE_UNCHANGED = 0,
	SANITIZE_CHANGED = 1,
};

static volatile sig_atomic_t running = 1;

struct dhcpv6_option_view {
	uint16_t code;
	uint16_t data_len;
	size_t total_len;
	uint8_t *start;
	uint8_t *data;
};

static int dhcpv6_option_parse(uint8_t *cursor, uint8_t *end,
                               struct dhcpv6_option_view *option,
                               char *error, size_t error_len)
{
	const size_t header_len = sizeof(struct dhcpv6_option_header_wire);
	struct dhcpv6_option_header_wire *header;
	uint16_t data_len;
	uint8_t *data;

	if (cursor > end || (size_t)(end - cursor) < header_len) {
		set_error(error, error_len, "truncated DHCPv6 option header");
		return -1;
	}

	header = (struct dhcpv6_option_header_wire *)cursor;
	option->code = ntohs(header->code);
	data_len = ntohs(header->length);
	data = cursor + header_len;

	if ((size_t)data_len > (size_t)(end - data)) {
		set_error(error, error_len, "DHCPv6 option %u overruns packet",
		          option->code);
		return -1;
	}

	option->data_len = data_len;
	option->total_len = header_len + (size_t)data_len;
	option->start = cursor;
	option->data = data;
	return 0;
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

static enum packet_type
detect_packet_type(struct pkt_buff *pktb, struct ip6_hdr *ip6h)
{
	if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
		struct nd_router_advert *ra;
		uint8_t *packet_end;
		uint8_t *transport;

		if (!nfq_ip6_set_transport_header(pktb, ip6h, IPPROTO_ICMPV6))
			return PACKET_OTHER;

		transport = pktb_transport_header(pktb);
		if (transport == NULL)
			return PACKET_OTHER;

		packet_end = (uint8_t *)pktb_data(pktb) + pktb_len(pktb);
		if (transport > packet_end ||
		    (size_t)(packet_end - transport) < sizeof(*ra))
			return PACKET_OTHER;

		ra = (struct nd_router_advert *)transport;
		if (ra->nd_ra_type == ND_ROUTER_ADVERT &&
		    ra->nd_ra_code == ND_ROUTER_ADVERT_CODE)
			return PACKET_RA;

		return PACKET_OTHER;
	}

	if (ip6h->ip6_nxt == IPPROTO_UDP) {
		struct udphdr *udp;

		if (!nfq_ip6_set_transport_header(pktb, ip6h, IPPROTO_UDP))
			return PACKET_OTHER;

		udp = nfq_udp_get_hdr(pktb);
		if (udp == NULL)
			return PACKET_OTHER;

		if (ntohs(udp->source) == DHCPV6_SERVER_PORT &&
		    ntohs(udp->dest) == DHCPV6_CLIENT_PORT)
			return PACKET_DHCPV6;
	}

	return PACKET_OTHER;
}

/*
 * Remove bytes from the end of an IPv6 transport payload. Keep the
 * libnetfilter_queue offset arithmetic here so sanitizer code works with
 * named packet pointers and lengths only.
 */
static int shrink_ipv6_transport(struct pkt_buff *pktb, uint8_t *transport,
                                 size_t new_transport_len,
                                 size_t original_transport_len)
{
	uint8_t *network = pktb_data(pktb);
	size_t transport_from_network;
	size_t remove_len;

	if (new_transport_len > original_transport_len || transport < network)
		return 0;
	if (new_transport_len == original_transport_len)
		return 1;

	transport_from_network = (size_t)(transport - network);
	if (transport_from_network > pktb_len(pktb))
		return 0;

	remove_len = original_transport_len - new_transport_len;
	return nfq_ip6_mangle(pktb,
	                      (unsigned int)transport_from_network,
	                      (unsigned int)new_transport_len,
	                      (unsigned int)remove_len, "", 0U);
}

/*
 * Sanitize a packet already classified as a Router Advertisement.
 */
static enum sanitize_result
sanitize_ra(struct pkt_buff *pktb, struct ip6_hdr *ip6h,
            const struct in6_addr *local_dns, const char *endpoints,
            char *detail, size_t detail_len, char *error, size_t error_len)
{
	struct nd_router_advert *ra;
	struct option_compactor compactor;
	uint8_t *icmp_bytes;
	uint8_t *packet_end;
	uint8_t *options;
	uint8_t *options_end;
	size_t icmp_len;
	size_t options_len;
	size_t new_options_len;
	uint16_t original_lifetime;
	unsigned int rdnss_options = 0;
	unsigned int rdnss_addresses = 0;
	unsigned int rdnss_rewritten = 0;
	unsigned int rdnss_deduplicated;
	unsigned int dnssl_removed = 0;
	bool kept_rdnss = false;
	bool router_lifetime_changed;
	bool changed;
	bool log_details = detail != NULL && detail_len != 0;
	struct addr_list original_rdnss;

	icmp_bytes = pktb_transport_header(pktb);
	if (icmp_bytes == NULL) {
		set_error(error, error_len, "RA transport header unavailable");
		return SANITIZE_ERROR;
	}

	packet_end = (uint8_t *)pktb_data(pktb) + pktb_len(pktb);
	if (icmp_bytes > packet_end) {
		set_error(error, error_len, "RA transport header outside packet");
		return SANITIZE_ERROR;
	}
	icmp_len = (size_t)(packet_end - icmp_bytes);

	if (icmp_len < sizeof(struct nd_router_advert)) {
		set_error(error, error_len, "truncated Router Advertisement");
		return SANITIZE_ERROR;
	}

	ra = (struct nd_router_advert *)icmp_bytes;

	if (ip6h->ip6_hlim != ND_ROUTER_ADVERT_REQUIRED_HOP_LIMIT) {
		set_error(error, error_len,
		          "RA hop limit %u is not %u", ip6h->ip6_hlim,
		          ND_ROUTER_ADVERT_REQUIRED_HOP_LIMIT);
		return SANITIZE_ERROR;
	}

	original_lifetime = ntohs(ra->nd_ra_router_lifetime);
	router_lifetime_changed =
		original_lifetime != RA_NEUTRAL_ROUTER_LIFETIME;
	if (router_lifetime_changed)
		ra->nd_ra_router_lifetime = htons(RA_NEUTRAL_ROUTER_LIFETIME);

	if (log_details)
		addr_list_init(&original_rdnss);

	options = icmp_bytes + sizeof(*ra);
	options_len = icmp_len - sizeof(*ra);
	options_end = options + options_len;
	option_compactor_init(&compactor, options);

	/*
	 * Compact the RA option stream in place while walking it once:
	 *   - keep the first RDNSS, normalized to one local DNS address;
	 *   - skip later RDNSS options;
	 *   - skip DNSSL options;
	 *   - move unrelated options forward only after a gap is created.
	 *
	 * pktb is a private packet copy, so a malformed option discovered later
	 * can still fail open without exposing any partial edits.
	 */
	while (compactor.read < options_end) {
		struct nd_option_header_wire *header;
		uint8_t *opt = compactor.read;
		size_t remaining = (size_t)(options_end - compactor.read);
		size_t opt_len;

		if (remaining < sizeof(*header)) {
			set_error(error, error_len, "truncated RA option header");
			return SANITIZE_ERROR;
		}

		header = (struct nd_option_header_wire *)opt;
		if (header->length_units == 0) {
			set_error(error, error_len, "zero-length RA option");
			return SANITIZE_ERROR;
		}

		opt_len = (size_t)header->length_units * NDP_OPTION_LEN_UNIT_OCTETS;
		if (opt_len > remaining) {
			set_error(error, error_len, "RA option overruns packet");
			return SANITIZE_ERROR;
		}

		if (header->type == ND_OPTION_DNSSL) {
			dnssl_removed++;
			option_compactor_skip(&compactor, opt_len);
			continue;
		}

		if (header->type == ND_OPTION_RDNSS) {
			const size_t fixed_len = sizeof(struct rdnss_option_wire);
			const size_t single_dns_len =
				fixed_len + sizeof(struct in6_addr);
			size_t address_bytes;

			if (opt_len < single_dns_len ||
			    (opt_len - fixed_len) % sizeof(struct in6_addr) != 0) {
				set_error(error, error_len,
				          "invalid RDNSS option length %zu", opt_len);
				return SANITIZE_ERROR;
			}

			address_bytes = opt_len - fixed_len;
			rdnss_addresses +=
				(unsigned int)(address_bytes / sizeof(struct in6_addr));

			if (log_details) {
				rdnss_options++;
				addr_list_append_wire_ipv6(&original_rdnss,
				                           opt + fixed_len,
				                           address_bytes);
			}

			if (kept_rdnss) {
				option_compactor_skip(&compactor, opt_len);
				continue;
			}

			rdnss_rewritten = memcmp(opt + fixed_len, local_dns,
			                         sizeof(*local_dns)) != 0;
			header->length_units =
				(uint8_t)(single_dns_len / NDP_OPTION_LEN_UNIT_OCTETS);
			memcpy(opt + fixed_len, local_dns, sizeof(*local_dns));
			option_compactor_keep_prefix(&compactor, single_dns_len,
			                             opt_len);
			kept_rdnss = true;
			continue;
		}

		option_compactor_keep(&compactor, opt_len);
	}

	rdnss_deduplicated =
		rdnss_addresses > 1U ? rdnss_addresses - 1U : 0U;
	changed =
		router_lifetime_changed ||
		rdnss_rewritten != 0 ||
		rdnss_deduplicated != 0 ||
		dnssl_removed != 0;

	if (!changed)
		return SANITIZE_UNCHANGED;

	new_options_len = option_compactor_output_len(&compactor);
	if (!shrink_ipv6_transport(pktb, icmp_bytes,
	                           sizeof(*ra) + new_options_len, icmp_len)) {
		set_error(error, error_len,
		          "libnetfilter_queue failed to compact RA options");
		return SANITIZE_ERROR;
	}

	icmp_len = sizeof(*ra) + new_options_len;

	/* All RA edits share one final ICMPv6 checksum calculation. */
	ip6h = nfq_ip6_get_hdr(pktb);
	icmp_bytes = pktb_transport_header(pktb);
	if (ip6h == NULL || icmp_bytes == NULL) {
		set_error(error, error_len, "RA headers unavailable after compaction");
		return SANITIZE_ERROR;
	}
	ra = (struct nd_router_advert *)icmp_bytes;
	ra->nd_ra_cksum = 0;
	ra->nd_ra_cksum = htons(icmpv6_checksum(ip6h, icmp_bytes, icmp_len));

	if (log_details)
		format_ra_log_detail(detail, detail_len, endpoints, original_lifetime,
		                     RA_NEUTRAL_ROUTER_LIFETIME, &original_rdnss,
		                     rdnss_options, rdnss_rewritten,
		                     rdnss_deduplicated, dnssl_removed);

	return SANITIZE_CHANGED;
}

/*
 * Sanitize a packet already classified as direct DHCPv6 server-to-client.
 */
static enum sanitize_result
sanitize_dhcpv6(struct pkt_buff *pktb, const struct in6_addr *local_dns,
                const char *endpoints, char *detail, size_t detail_len,
                char *error, size_t error_len)
{
	struct ip6_hdr *ip6h;
	struct udphdr *udp;
	struct option_compactor compactor;
	uint8_t *dhcp;
	struct dhcpv6_direct_header_wire *message;
	uint8_t *options_start;
	uint8_t *options_end;
	size_t available_udp_payload;
	size_t dhcp_len;
	size_t new_dhcp_len;
	uint16_t udp_len;
	uint8_t msg_type;
	unsigned int dns_options = 0;
	unsigned int dns_addresses = 0;
	unsigned int dns_rewritten = 0;
	unsigned int dns_deduplicated;
	unsigned int domain_search_removed = 0;
	bool kept_dns = false;
	bool changed;
	bool log_details = detail != NULL && detail_len != 0;
	uint8_t transaction_id[DHCPV6_TRANSACTION_ID_LEN] = { 0 };
	char client_id[CLIENT_ID_BUFSIZE] = "";
	char client_mac[MAC_TEXT_BUFSIZE] = "";
	struct addr_list original_dns;

	udp = nfq_udp_get_hdr(pktb);
	if (udp == NULL) {
		set_error(error, error_len, "DHCPv6 UDP header unavailable");
		return SANITIZE_ERROR;
	}

	available_udp_payload = nfq_udp_get_payload_len(udp, pktb);
	udp_len = ntohs(udp->len);
	if (udp_len < sizeof(*udp) ||
	    (size_t)udp_len - sizeof(*udp) > available_udp_payload) {
		set_error(error, error_len, "invalid UDP length %u", udp_len);
		return SANITIZE_ERROR;
	}

	dhcp = nfq_udp_get_payload(udp, pktb);
	if (dhcp == NULL) {
		set_error(error, error_len, "DHCPv6 UDP payload unavailable");
		return SANITIZE_ERROR;
	}
	dhcp_len = (size_t)udp_len - sizeof(*udp);

	if (dhcp_len < sizeof(struct dhcpv6_direct_header_wire)) {
		set_error(error, error_len, "truncated DHCPv6 direct-message header");
		return SANITIZE_ERROR;
	}

	message = (struct dhcpv6_direct_header_wire *)dhcp;
	msg_type = message->message_type;
	if (msg_type == DHCPV6_RELAY_FORWARD || msg_type == DHCPV6_RELAY_REPLY)
		return SANITIZE_UNCHANGED;

	if (log_details) {
		memcpy(transaction_id, message->transaction_id, sizeof(transaction_id));
		addr_list_init(&original_dns);
	}

	options_start = dhcp + sizeof(*message);
	options_end = dhcp + dhcp_len;
	option_compactor_init(&compactor, options_start);

	/*
	 * Compact the top-level DHCPv6 option stream in place while walking it once:
	 *   - keep the first DNS option, normalized to one local DNS address;
	 *   - skip later DNS options;
	 *   - skip Domain Search List options;
	 *   - move unrelated options forward only after a gap is created.
	 */
	while (compactor.read < options_end) {
		struct dhcpv6_option_view option;

		if (dhcpv6_option_parse(compactor.read, options_end,
		                        &option, error, error_len) < 0)
			return SANITIZE_ERROR;

		if (log_details && option.code == DHCPV6_OPT_CLIENTID &&
		    client_id[0] == '\0') {
			format_dhcpv6_client_log_fields(option.data, option.data_len,
			                                client_id, sizeof(client_id),
			                                client_mac, sizeof(client_mac));
		}

		if (option.code == DHCPV6_OPT_DOMAIN_LIST) {
			domain_search_removed++;
			option_compactor_skip(&compactor, option.total_len);
			continue;
		}

		if (option.code == DHCPV6_OPT_DNS_SERVERS) {
			struct dhcpv6_option_header_wire *header;
			uint8_t *opt;
			const size_t fixed_len =
				sizeof(struct dhcpv6_option_header_wire);
			const size_t single_dns_len =
				fixed_len + sizeof(struct in6_addr);

			if (option.data_len == 0 ||
			    option.data_len % sizeof(struct in6_addr) != 0) {
				set_error(error, error_len,
				          "invalid DHCPv6 DNS option length %u",
				          option.data_len);
				return SANITIZE_ERROR;
			}

			dns_addresses +=
				(unsigned int)(option.data_len / sizeof(struct in6_addr));

			if (log_details) {
				dns_options++;
				addr_list_append_wire_ipv6(&original_dns,
				                           option.data,
				                           option.data_len);
			}

			if (kept_dns) {
				option_compactor_skip(&compactor, option.total_len);
				continue;
			}

			dns_rewritten = memcmp(option.data, local_dns,
			                       sizeof(*local_dns)) != 0;
			opt = option.start;
			header = (struct dhcpv6_option_header_wire *)opt;
			header->length = htons((uint16_t)sizeof(struct in6_addr));
			memcpy(opt + fixed_len, local_dns, sizeof(*local_dns));
			option_compactor_keep_prefix(&compactor, single_dns_len,
			                             option.total_len);
			kept_dns = true;
			continue;
		}

		option_compactor_keep(&compactor, option.total_len);
	}

	dns_deduplicated = dns_addresses > 1U ? dns_addresses - 1U : 0U;
	changed =
		dns_rewritten != 0 ||
		dns_deduplicated != 0 ||
		domain_search_removed != 0;

	if (!changed)
		return SANITIZE_UNCHANGED;

	new_dhcp_len = sizeof(*message) + option_compactor_output_len(&compactor);
	if (new_dhcp_len < dhcp_len) {
		if (!nfq_udp_mangle_ipv6(pktb, (unsigned int)new_dhcp_len,
		                         (unsigned int)(dhcp_len - new_dhcp_len),
		                         "", 0U)) {
			set_error(error, error_len,
			          "libnetfilter_queue failed to compact DHCPv6 options");
			return SANITIZE_ERROR;
		}
	} else {
		/*
		 * A same-length DNS replacement does not need a mangle operation,
		 * but its UDP checksum still covers the changed payload.
		 */
		ip6h = nfq_ip6_get_hdr(pktb);
		udp = nfq_udp_get_hdr(pktb);
		if (ip6h == NULL || udp == NULL) {
			set_error(error, error_len,
			          "DHCPv6 headers unavailable for checksum update");
			return SANITIZE_ERROR;
		}
		nfq_udp_compute_checksum_ipv6(udp, ip6h);
	}

	/* A computed UDP checksum of zero is transmitted as all ones. */
	udp = nfq_udp_get_hdr(pktb);
	if (udp == NULL) {
		set_error(error, error_len, "UDP header unavailable after compaction");
		return SANITIZE_ERROR;
	}
	if (udp->check == 0)
		udp->check = htons(UINT16_MAX);

	if (log_details)
		format_dhcpv6_log_detail(detail, detail_len, msg_type, endpoints,
		                         transaction_id, client_id, client_mac,
		                         &original_dns, dns_options, dns_rewritten,
		                         dns_deduplicated, domain_search_removed);

	return SANITIZE_CHANGED;
}

static int accept_unchanged(struct nfq_q_handle *qh, uint32_t id,
                            struct pkt_buff *pktb)
{
	if (pktb != NULL)
		pktb_free(pktb);

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/*
 * A replacement verdict carries NFQA_PAYLOAD only. For bridge-family packets
 * the kernel retains the original L2/VLAN metadata separately, so return the
 * modified IPv6 packet exactly as nfq_get_payload() exposed it.
 */
static int verdict_with_modified_ipv6(struct nfq_q_handle *qh, uint32_t id,
                                      struct pkt_buff *pktb)
{
	return nfq_set_verdict(qh, id, NF_ACCEPT,
	                       (uint32_t)pktb_len(pktb), pktb_data(pktb));
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
	struct ipv6_packet_view ipv6;
	struct ip6_hdr *ip6h;
	struct in6_addr local_dns;
	char dns_ifname[IF_NAMESIZE] = "";
	char local_dns_log[LOCAL_DNS_TEXT_BUFSIZE] = "";
	char endpoints[ENDPOINT_BUFSIZE];
	char detail[DETAIL_BUFSIZE] = "";
	char error[ERROR_BUFSIZE] = "";
	uint32_t id = 0;
	uint32_t indev;
	uint32_t physindev;
	int payload_len;
	int verdict;
	enum packet_type packet_type;
	enum sanitize_result result;

	(void)nfmsg;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph != NULL)
		id = ntohl(ph->packet_id);

	payload_len = nfq_get_payload(nfa, &payload);
	if (payload_len <= 0 || payload == NULL) {
		log_error("id=%u: NFQUEUE payload unavailable; ACCEPT unchanged", id);
		return accept_unchanged(qh, id, pktb);
	}

	if (parse_nfqueue_ipv6_payload(payload, (size_t)payload_len, &ipv6) < 0) {
		log_error("id=%u: invalid NFQUEUE IPv6 payload; ACCEPT unchanged", id);
		return accept_unchanged(qh, id, pktb);
	}

	pktb = pktb_alloc(AF_INET6, ipv6.data, ipv6.len, 0);
	if (pktb == NULL) {
		log_error("id=%u: pktb_alloc() failed; ACCEPT unchanged", id);
		return accept_unchanged(qh, id, pktb);
	}

	ip6h = nfq_ip6_get_hdr(pktb);
	if (ip6h == NULL) {
		log_error("id=%u: libnetfilter_queue rejected IPv6 header; ACCEPT unchanged",
		          id);
		return accept_unchanged(qh, id, pktb);
	}

	packet_type = detect_packet_type(pktb, ip6h);
	if (packet_type == PACKET_OTHER) {
		return accept_unchanged(qh, id, pktb);
	}

	if (ctx->verbose)
		format_endpoints(ip6h, endpoints, sizeof(endpoints));

	indev = nfq_get_indev(nfa);
	physindev = nfq_get_physindev(nfa);
	if (resolve_local_dns(indev, physindev, &local_dns,
	                      ctx->verbose ? dns_ifname : NULL,
	                      ctx->verbose ? sizeof(dns_ifname) : 0U) < 0) {
		log_error("id=%u: no ULA found on ingress interface or bridge master; "
		          "ACCEPT unchanged", id);
		return accept_unchanged(qh, id, pktb);
	}

	if (ctx->verbose)
		format_local_dns_log(&local_dns, dns_ifname,
		                     local_dns_log, sizeof(local_dns_log));

	switch (packet_type) {
	case PACKET_RA:
		result = sanitize_ra(pktb, ip6h, &local_dns,
		                     ctx->verbose ? endpoints : NULL,
		                     ctx->verbose ? detail : NULL,
		                     ctx->verbose ? sizeof(detail) : 0U,
		                     error, sizeof(error));
		break;
	case PACKET_DHCPV6:
		result = sanitize_dhcpv6(pktb, &local_dns,
		                         ctx->verbose ? endpoints : NULL,
		                         ctx->verbose ? detail : NULL,
		                         ctx->verbose ? sizeof(detail) : 0U,
		                         error, sizeof(error));
		break;
	case PACKET_OTHER:
	default:
		result = SANITIZE_UNCHANGED;
		break;
	}

	if (result == SANITIZE_ERROR) {
		log_error("id=%u: %s; ACCEPT unchanged",
		          id, error[0] ? error : "packet sanitizer failed");
		return accept_unchanged(qh, id, pktb);
	}

	if (result == SANITIZE_UNCHANGED) {
		return accept_unchanged(qh, id, pktb);
	}

	if (ctx->verbose)
		log_info("id=%u local-dns=%s %s", id, local_dns_log, detail);

	verdict = verdict_with_modified_ipv6(qh, id, pktb);
	if (verdict < 0) {
		log_error("id=%u: could not construct modified IPv6 verdict; "
		          "ACCEPT unchanged", id);
		return accept_unchanged(qh, id, pktb);
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

	log_info("vxlan-ipv6-sanitize: starting");

	if (install_signal_handlers() < 0) {
		log_error("failed to install signal handlers: %s", strerror(errno));
		exit_status = EXIT_FAILURE;
		goto out;
	}

	h = nfq_open();
	if (h == NULL) {
		log_error("nfq_open() failed");
		exit_status = EXIT_FAILURE;
		goto out;
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
	 * fail-open flag as well.
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

	log_info("vxlan-ipv6-sanitize: listening on NFQUEUE %u", QUEUE_NUM);

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

	log_info("vxlan-ipv6-sanitize: stopping");

out_queue:
	if (qh != NULL)
		nfq_destroy_queue(qh);
out_nfq:
	if (h != NULL)
		nfq_close(h);
out:
	log_info("vxlan-ipv6-sanitize: exiting");
	return exit_status;
}
