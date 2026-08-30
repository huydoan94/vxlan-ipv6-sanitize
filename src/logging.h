#ifndef VXLAN_IPV6_SANITIZE_LOGGING_H
#define VXLAN_IPV6_SANITIZE_LOGGING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#define ADDR_LIST_BUFSIZE 512U
#define MAC_TEXT_BUFSIZE (ETH_ALEN * 3U)
#define CLIENT_ID_BUFSIZE 384U
#define DETAIL_BUFSIZE 1536U
#define ERROR_BUFSIZE 256U
#define ENDPOINT_BUFSIZE 256U

struct addr_list {
	char buf[ADDR_LIST_BUFSIZE];
	size_t len;
	bool first;
	bool truncated;
};

__attribute__((format(printf, 2, 3)))
void log_info(bool verbose, const char *fmt, ...);

__attribute__((format(printf, 1, 2)))
void log_error(const char *fmt, ...);

__attribute__((format(printf, 3, 4)))
void set_error(char *buf, size_t len, const char *fmt, ...);

void format_endpoints(const uint8_t *packet, size_t packet_len,
		      size_t ipv6_offset, const struct ip6_hdr *ip6h,
		      char *buf, size_t len);

void addr_list_init(struct addr_list *list);
void addr_list_append(struct addr_list *list, const struct in6_addr *addr);

void format_hex(const uint8_t *data, size_t data_len,
		char *buf, size_t buf_len);
void duid_ethernet_mac(const uint8_t *duid, size_t len,
		       char *buf, size_t buf_len);

void format_ra_log_detail(char *detail, size_t detail_len,
			  const char *endpoints,
			  uint16_t original_lifetime,
			  uint16_t new_lifetime,
			  struct addr_list *original_rdnss,
			  struct addr_list *modified_rdnss,
			  unsigned int rewritten);

void format_dhcpv6_log_detail(char *detail, size_t detail_len,
			      uint8_t msg_type,
			      const char *endpoints,
			      const uint8_t *transaction_id,
			      const char *client_id,
			      const char *client_mac,
			      struct addr_list *original_dns,
			      struct addr_list *modified_dns,
			      unsigned int dns_options,
			      unsigned int rewritten);

#endif
