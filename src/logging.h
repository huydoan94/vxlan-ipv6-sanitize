#ifndef VXLAN_IPV6_SANITIZE_LOGGING_H
#define VXLAN_IPV6_SANITIZE_LOGGING_H

#include <stdbool.h>
#include <stddef.h>

__attribute__((format(printf, 2, 3)))
void log_info(bool verbose, const char *fmt, ...);

__attribute__((format(printf, 1, 2)))
void log_error(const char *fmt, ...);

__attribute__((format(printf, 3, 4)))
void set_error(char *buf, size_t len, const char *fmt, ...);

#endif
