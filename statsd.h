#ifndef _H_STATSD_CLIENT
#define _H_STATSD_CLIENT
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

struct _statsd_link  {
    struct sockaddr_in server;
    int sock;
    char *ns;
    char *tags;
};

typedef struct _statsd_link statsd_link;


statsd_link *statsd_init(const char *host, int port);
statsd_link *statsd_init_with_namespace(const char *host, int port, const char *ns);
statsd_link *statsd_init_with_tags(const char *host, int port, const char *tags);
statsd_link *statsd_init_with_namespace_tags(const char *host, int port, const char *ns, const char *tags);
void statsd_finalize(statsd_link *link);

/*
  write the stat line to the provided buffer,
  type can be "c", "g" or "ms"
  lf - whether line feed needs to be added
 */
void statsd_prepare(statsd_link *link, char *stat, size_t value, const char *type, float sample_rate, char *buf, size_t buflen, int lf);

/* manually send a message, which might be composed of several lines. Must be null-terminated */
int statsd_send(statsd_link *link, const char *message);

int statsd_inc(statsd_link *link, char *stat, float sample_rate);
int statsd_dec(statsd_link *link, char *stat, float sample_rate);
int statsd_count(statsd_link *link, char *stat, size_t count, float sample_rate);
int statsd_gauge(statsd_link *link, char *stat, size_t value);
int statsd_timing(statsd_link *link, char *stat, size_t ms);
int statsd_timing_with_sample_rate(statsd_link *link, char *stat, size_t ms, float sample_rate);
#endif