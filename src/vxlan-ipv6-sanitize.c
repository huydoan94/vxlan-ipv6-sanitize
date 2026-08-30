#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
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
#include <libnetfilter_queue/libnetfilter_queue_icmp.h>
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

#define DHCPV6_SERVER_PORT 547U
#define DHCPV6_CLIENT_PORT 546U
#define DHCPV6_OPT_CLIENTID 1U
#define DHCPV6_OPT_DNS_SERVERS 23U

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

static volatile sig_atomic_t running = 1;

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

/*
 * Return 1 when changed, 0 when this is not a supported RA or no change is
 * required, and -1 for a malformed RA that must be accepted unchanged.
 */
static int sanitize_ra(struct pkt_buff *pktb, struct ip6_hdr *ip6h,
		       const struct in6_addr *local_dns,
		       const char *endpoints,
		       char *detail, size_t detail_len,
		       char *error, size_t error_len)
{
	struct icmphdr *generic_icmp;
	struct nd_router_advert *ra;
	uint8_t *icmp_bytes;
	uint8_t *opts;
	size_t icmp_offset;
	size_t icmp_len;
	size_t opts_len;
	size_t opt_offset;
	uint16_t original_lifetime;
	unsigned int rewritten = 0;
	bool changed = false;
	struct addr_list original_rdnss;
	struct addr_list modified_rdnss;

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

	ra = (struct nd_router_advert *)icmp_bytes;
	opts = icmp_bytes + sizeof(*ra);
	opts_len = icmp_len - sizeof(*ra);

	if (validate_nd_options(opts, opts_len) < 0) {
		set_error(error, error_len, "malformed RA option stream");
		return -1;
	}

	original_lifetime = ntohs(ra->nd_ra_router_lifetime);
	if (original_lifetime != RA_NEUTRAL_ROUTER_LIFETIME) {
		ra->nd_ra_router_lifetime = htons(RA_NEUTRAL_ROUTER_LIFETIME);
		changed = true;
	}

	addr_list_init(&original_rdnss);
	addr_list_init(&modified_rdnss);

	for (opt_offset = 0; opt_offset < opts_len; ) {
		struct nd_option_header_wire *header;
		uint8_t *opt = opts + opt_offset;
		size_t opt_len;
		const size_t fixed_len = offsetof(struct rdnss_option_wire, addresses);
		const size_t minimum_len = fixed_len + sizeof(struct in6_addr);
		size_t addr_offset;

		header = (struct nd_option_header_wire *)opt;
		opt_len = (size_t)header->length_units * NDP_OPTION_LEN_UNIT_OCTETS;

		if (header->type != ND_OPTION_RDNSS) {
			opt_offset += opt_len;
			continue;
		}

		/* RFC 8106: fixed fields followed by one or more IPv6 addresses. */
		if (opt_len < minimum_len ||
		    (opt_len - fixed_len) % sizeof(struct in6_addr) != 0) {
			set_error(error, error_len,
				  "invalid RDNSS option length %zu", opt_len);
			return -1;
		}

		for (addr_offset = fixed_len;
		     addr_offset < opt_len;
		     addr_offset += sizeof(struct in6_addr)) {
			struct in6_addr old_addr;
			uint8_t *wire_addr = opt + addr_offset;

			memcpy(&old_addr, wire_addr, sizeof(old_addr));
			addr_list_append(&original_rdnss, &old_addr);

			if (memcmp(wire_addr, local_dns, sizeof(*local_dns)) != 0) {
				memcpy(wire_addr, local_dns, sizeof(*local_dns));
				rewritten++;
				changed = true;
			}

			addr_list_append(&modified_rdnss, local_dns);
		}

		opt_offset += opt_len;
	}

	if (!changed)
		return 0;

	/* Recalculate the checksum after the in-place RA modifications. */
	ra->nd_ra_cksum = 0;
	ra->nd_ra_cksum = htons(icmpv6_checksum(ip6h, icmp_bytes, icmp_len));

	format_ra_log_detail(detail, detail_len, endpoints, original_lifetime,
			     RA_NEUTRAL_ROUTER_LIFETIME, &original_rdnss,
			     &modified_rdnss, rewritten);

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

	format_dhcpv6_log_detail(
		detail, detail_len, msg_type, endpoints,
		dhcp + offsetof(struct dhcpv6_direct_header_wire, transaction_id),
		client_id, client_mac, &original_dns, &modified_dns,
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

	changed = sanitize_ra(pktb, ip6h, &local_dns,
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

	log_info(ctx->verbose, "id=%u local-dns=%s(%s) %s",
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

	log_info(ctx.verbose, "vxlan-ipv6-sanitize listening on NFQUEUE %u", QUEUE_NUM);

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

	log_info(ctx.verbose, "stopping");

out_queue:
	if (qh != NULL)
		nfq_destroy_queue(qh);
out_nfq:
	if (h != NULL)
		nfq_close(h);
out:
	return exit_status;
}
