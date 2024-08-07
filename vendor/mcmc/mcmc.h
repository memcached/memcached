#ifndef MCMC_HEADER
#define MCMC_HEADER

#include <sys/uio.h>
#include <stdint.h>

// Allow exposing normally static functions to a test suite running in a
// different module.
#ifdef MCMC_TEST
#define MCMC_STATIC
#else
#define MCMC_STATIC static
#endif

#define MCMC_OK 0
#define MCMC_NOK -2
#define MCMC_ERR -1
#define MCMC_NOT_CONNECTED 1
#define MCMC_CONNECTED 2
#define MCMC_CONNECTING 3 // nonblock mode.
#define MCMC_WANT_WRITE 4
#define MCMC_WANT_READ 5
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
#define MCMC_CODE_END 17
#define MCMC_ERR_SHORT 18
#define MCMC_ERR_PARSE 19
#define MCMC_ERR_VALUE 20
#define MCMC_CODE_ERROR 21
#define MCMC_CODE_CLIENT_ERROR 22
#define MCMC_CODE_SERVER_ERROR 23

// response types
#define MCMC_RESP_GET 100
#define MCMC_RESP_META 101
#define MCMC_RESP_STAT 102
#define MCMC_RESP_GENERIC 104
#define MCMC_RESP_END 105
#define MCMC_RESP_VERSION 106
#define MCMC_RESP_NUMERIC 107 // for weird incr/decr syntax.
#define MCMC_RESP_ERRMSG 108 // ERROR, CLIENT_ERROR, SERVER_ERRROR
#define MCMC_RESP_FAIL 109 // Complete failure to parse, garbage, etc

#define MCMC_OPTION_BLANK 0
#define MCMC_OPTION_NONBLOCK 1
#define MCMC_OPTION_TCP_KEEPALIVE (1<<1)

// convenience defines. if you want to save RAM you can set these smaller and
// error handler will only copy what you ask for.
#define MCMC_ERROR_CODE_MAX 32
#define MCMC_ERROR_MSG_MAX 512

#define MCMC_TOKTO_OK 0
#define MCMC_TOKTO_ERANGE -1
#define MCMC_TOKTO_ELONG -2
#define MCMC_TOKTO_EINVALID -3

typedef struct mcmc_resp_s {
    short type;
    short code;
    char *value; // pointer to start of value in buffer.
    size_t reslen; // full length of the response line
    size_t vlen_read; // amount of value that was in supplied buffer.
    size_t vlen; // reslen + vlen is the full length of the response.
    union {
        // META response
        struct {
            const char *rline; // start of meta response line.
            size_t rlen;
        };
        // GET response
        struct {
            const char *key;
            size_t klen;
            uint32_t flags;
            uint64_t cas;
            // TODO: value info
        };
        // STAT response
        struct {
            const char *sname;
            size_t snamelen;
            const char *stat;
            size_t statlen;
        };
    };
} mcmc_resp_t;

#define MCMC_PARSER_MAX_TOKENS 24
#define MCMC_PARSER_MFLAG_HAS_SPACE (1)
#define MCMC_PARSER_MFLAG_NOREPLY (1<<1)

typedef struct mcmc_tokenizer_s {
    uint8_t ntokens;
    uint8_t mstart; // token where meta flags begin
    uint16_t tokens[MCMC_PARSER_MAX_TOKENS]; // offsets for start of each token
    uint64_t metaflags;
} mcmc_tokenizer_t;

typedef struct mcmc_req_s {
    const char *request;
    uint8_t command;
    uint8_t cmd_type; // command class.
    // FIXME: see if we can map this from command or CMD_TYPE
    uint8_t keytoken; // because GAT. sigh. also cmds without a key.
    uint8_t klen; // length of key.
    uint8_t modeflags; // special indicators (noreply/etc)
    int16_t llen; // full length of the protocol line
    int32_t vlen; // length of the value if there is one
} mcmc_req_t;

int mcmc_fd(void *c);
size_t mcmc_size(int options);
size_t mcmc_min_buffer_size(int options);
int mcmc_parse_buf(const char *buf, size_t read, mcmc_resp_t *r);
int mcmc_connect(void *c, char *host, char *port, int options);
int mcmc_check_nonblock_connect(void *c, int *err);
int mcmc_send_request(void *c, const char *request, int len, int count);
int mcmc_request_writev(void *c, const struct iovec *iov, int iovcnt, ssize_t *sent, int count);
//int mcmc_read(void *c, char *buf, size_t bufsize, mcmc_resp_t *r);
//int mcmc_read_value(void *c, char *val, mcmc_resp_t *r, int *read);
int mcmc_disconnect(void *c);
void mcmc_get_error(void *c, char *code, size_t clen, char *msg, size_t mlen);

// TODO: experimental interface. high chance of changing.
// all meta results are of format "XX m e t a", so if we know it's a result we
// know where to start on the meta tokens.
// For full usage this should probably also be supplied with a "mcmc_res_t" so
// it can figure out what to call.
int mcmc_tokenize_res(const char *l, size_t len, mcmc_tokenizer_t *t);
#define mcmc_token_count(t) (t->ntokens)
const char *mcmc_token_get(const char *l, mcmc_tokenizer_t *t, int idx, int *len);
int mcmc_token_get_u32(const char *l, mcmc_tokenizer_t *t, int idx, uint32_t *val);
int mcmc_token_get_u64(const char *l, mcmc_tokenizer_t *t, int idx, uint64_t *val);
int mcmc_token_get_32(const char *l, mcmc_tokenizer_t *t, int idx, int32_t *val);
int mcmc_token_get_64(const char *l, mcmc_tokenizer_t *t, int idx, int64_t *val);
int mcmc_token_has_flag(const char *l, mcmc_tokenizer_t *t, char flag);
#define mcmc_token_has_flag_bit(t, f) (((t)->metaflags & f) ? MCMC_OK : MCMC_NOK)
const char *mcmc_token_get_flag(const char *l, mcmc_tokenizer_t *t, char flag, int *len);
int mcmc_token_get_flag_u32(const char *l, mcmc_tokenizer_t *t, char flag, uint32_t *val);
int mcmc_token_get_flag_u64(const char *l, mcmc_tokenizer_t *t, char flag, uint64_t *val);
int mcmc_token_get_flag_32(const char *l, mcmc_tokenizer_t *t, char flag, int32_t *val);
int mcmc_token_get_flag_64(const char *l, mcmc_tokenizer_t *t, char flag, int64_t *val);
int mcmc_token_get_flag_idx(const char *l, mcmc_tokenizer_t *t, char flag);

#ifdef MCMC_TEST
int mcmc_toktou32(const char *t, size_t len, uint32_t *out);
int mcmc_toktou64(const char *t, size_t len, uint64_t *out);
int mcmc_tokto32(const char *t, size_t len, int32_t *out);
int mcmc_tokto64(const char *t, size_t len, int64_t *out);
int _mcmc_tokenize_meta(mcmc_tokenizer_t *t, const char *line, size_t len, const int mstart, const int max);
int _mcmc_token_len(const char *line, mcmc_tokenizer_t *t, size_t token);
const char *_mcmc_token(const char *line, mcmc_tokenizer_t *t, size_t token, int *len);
#endif

#endif // MCMC_HEADER
