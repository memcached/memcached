#ifndef AUTHFILE_H
#define AUTHFILE_H

enum authfile_ret {
    AUTHFILE_OK = 0,
    AUTHFILE_OOM,
    AUTHFILE_STATFAIL, // not likely, but just to be sure
    AUTHFILE_OPENFAIL,
    AUTHFILE_MALFORMED,
};

// FIXME: mc_authfile or something?
enum authfile_ret authfile_load(const char *file);
int authfile_check(const char *user, const char *pass);

#endif /* AUTHFILE_H */
