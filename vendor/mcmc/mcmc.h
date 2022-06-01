#ifndef MCMC_HEADER
#define MCMC_HEADER

#define MCMC_OK 0
#define MCMC_ERR -1
#define MCMC_NOT_CONNECTED 1
#define MCMC_CONNECTED 2
#define MCMC_CONNECTING 3 // nonblock mode.
#define MCMC_WANT_WRITE 4
#define MCMC_WANT_READ 5
#define MCMC_HAS_RESULT 7
// TODO: either internally set a flag for "ok" or "not ok" and use a func,
// or use a bitflag here (1<<6) for "OK", (1<<5) for "FAIL", etc.
// or, we directly return "OK" or "FAIL" and you can ask for specific error.
#define MCMC_CODE_STORED 8
#define MCMC_CODE_EXISTS 9
#define MCMC_CODE_DELETED 10
#define MCMC_CODE_TOUCHED 11
#define MCMC_CODE_VERSION 12
#define MCMC_CODE_NOT_FOUND 13
#define MCMC_CODE_NOT_STORED 14
#define MCMC_CODE_OK 15
#define MCMC_CODE_NOP 16
#define MCMC_PARSE_ERROR_SHORT 17
#define MCMC_PARSE_ERROR 18
#define MCMC_CODE_MISS 19 // FIXME


// response types
#define MCMC_RESP_GET 100
#define MCMC_RESP_META 101
#define MCMC_RESP_STAT 102
#define MCMC_RESP_GENERIC 104
#define MCMC_RESP_END 105
#define MCMC_RESP_VERSION 106
#define MCMC_RESP_NUMERIC 107 // for weird incr/decr syntax.

#define MCMC_OPTION_BLANK 0
#define MCMC_OPTION_NONBLOCK 1
#define MCMC_OPTION_TCP_KEEPALIVE (1<<1)

// convenience defines. if you want to save RAM you can set these smaller and
// error handler will only copy what you ask for.
#define MCMC_ERROR_CODE_MAX 32
#define MCMC_ERROR_MSG_MAX 512

typedef struct {
    unsigned short type;
    unsigned short code;
    char *value; // pointer to start of value in buffer.
    size_t reslen; // full length of the response line
    size_t vlen_read; // amount of value that was in supplied buffer.
    size_t vlen; // reslen + vlen is the full length of the response.
    union {
        // META response
        struct {
            char *rline; // start of meta response line.
            size_t rlen;
        };
        // GET response
        struct {
            char *key;
            size_t klen;
            uint32_t flags;
            uint64_t cas;
            // TODO: value info
        };
        // STAT response
        struct {
            char *stat;
            size_t slen;
        };
    };
} mcmc_resp_t;

int mcmc_fd(void *c);
size_t mcmc_size(int options);
size_t mcmc_min_buffer_size(int options);
int mcmc_parse_buf(void *c, char *buf, size_t read, mcmc_resp_t *r);
int mcmc_connect(void *c, char *host, char *port, int options);
int mcmc_check_nonblock_connect(void *c, int *err);
int mcmc_send_request(void *c, const char *request, int len, int count);
int mcmc_request_writev(void *c, const struct iovec *iov, int iovcnt, ssize_t *sent, int count);
//int mcmc_read(void *c, char *buf, size_t bufsize, mcmc_resp_t *r);
//int mcmc_read_value(void *c, char *val, mcmc_resp_t *r, int *read);
int mcmc_disconnect(void *c);
void mcmc_get_error(void *c, char *code, size_t clen, char *msg, size_t mlen);

#endif
