/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef VBUCKET_H
#define VBUCKET_H 1

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
    active = 1, /**< Actively servicing a vbucket. */
    replica, /**< Servicing a vbucket as a replica only. */
    pending, /**< Pending active. */
    dead /**< Not in use, pending deletion. */
} vbucket_state_t;

#ifdef __cplusplus
}
#endif
#endif
