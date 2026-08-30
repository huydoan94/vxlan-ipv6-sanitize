#include "logging.h"

#include <stdarg.h>
#include <stdio.h>

void log_info(bool verbose, const char *fmt, ...)
{
	va_list args;

	if (!verbose)
		return;

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
