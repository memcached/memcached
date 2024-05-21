#ifndef PROXY_TLS_H
#define PROXY_TLS_H

// Attempt to reduce ifdef soup within the larger code files by blanking out
// or swapping these specialized functions.
// I'm not being super smart about this: if usage of a function leads to a
// compile error just adjust this as necessary. This is a bit less typing than
// leaving the header empty and redefining everything in the .c file, but if
// the balance changes we should switch to always doing that.

enum mcp_tls_ret {
    MCP_TLS_OK = 1,
    MCP_TLS_NEEDIO = -1,
    MCP_TLS_ERR = -2,
};

#ifdef PROXY_TLS
int mcp_tls_init(proxy_ctx_t *ctx);
int mcp_tls_backend_init(proxy_ctx_t *ctx, struct mcp_backendconn_s *be);
int mcp_tls_shutdown(struct mcp_backendconn_s *be);
int mcp_tls_cleanup(struct mcp_backendconn_s *be);
int mcp_tls_connect(struct mcp_backendconn_s *be);
int mcp_tls_handshake(struct mcp_backendconn_s *be);
int mcp_tls_send_validate(struct mcp_backendconn_s *be);
int mcp_tls_read(struct mcp_backendconn_s *be);
int mcp_tls_writev(struct mcp_backendconn_s *be, int iovcnt);
#else
#define mcp_tls_init(ctx)
#define mcp_tls_backend_init(ctx, be)
#define mcp_tls_shutdown(be);
#define mcp_tls_cleanup(be);
#define mcp_tls_connect(be)
#define mcp_tls_handshake(be) 0
#define mcp_tls_send_validate(be) 0
#define mcp_tls_read(be) 0
int mcp_tls_writev(struct mcp_backendconn_s *be, int iovcnt);
#endif // PROXY_TLS

#endif
