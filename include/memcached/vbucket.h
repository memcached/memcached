/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef MEMCACHED_VBUCKET_H
#define MEMCACHED_VBUCKET_H 1

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
    vbucket_state_active = 1, /**< Actively servicing a vbucket. */
    vbucket_state_replica, /**< Servicing a vbucket as a replica only. */
    vbucket_state_pending, /**< Pending active. */
    vbucket_state_dead /**< Not in use, pending deletion. */
} vbucket_state_t;

#define is_valid_vbucket_state_t(state) \
    (state == vbucket_state_active || \
     state == vbucket_state_replica || \
     state == vbucket_state_pending || \
     state == vbucket_state_dead)

#ifdef __cplusplus
}
#endif
#endif
