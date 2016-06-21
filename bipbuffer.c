/**
 * Copyright (c) 2011, Willem-Hendrik Thiart
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.bipbuffer file.
 *
 * @file
 * @author  Willem Thiart himself@willemthiart.com
 */

#include "stdio.h"
#include <stdlib.h>

/* for memcpy */
#include <string.h>

#include "bipbuffer.h"

static size_t bipbuf_sizeof(const unsigned int size)
{
    return sizeof(bipbuf_t) + size;
}

int bipbuf_unused(const bipbuf_t* me)
{
    if (1 == me->b_inuse)
        /* distance between region B and region A */
        return me->a_start - me->b_end;
    else
        return me->size - me->a_end;
}

int bipbuf_size(const bipbuf_t* me)
{
    return me->size;
}

int bipbuf_used(const bipbuf_t* me)
{
    return (me->a_end - me->a_start) + me->b_end;
}

void bipbuf_init(bipbuf_t* me, const unsigned int size)
{
    me->a_start = me->a_end = me->b_end = 0;
    me->size = size;
    me->b_inuse = 0;
}

bipbuf_t *bipbuf_new(const unsigned int size)
{
    bipbuf_t *me = malloc(bipbuf_sizeof(size));
    if (!me)
        return NULL;
    bipbuf_init(me, size);
    return me;
}

void bipbuf_free(bipbuf_t* me)
{
    free(me);
}

int bipbuf_is_empty(const bipbuf_t* me)
{
    return me->a_start == me->a_end;
}

/* find out if we should turn on region B
 * ie. is the distance from A to buffer's end less than B to A? */
static void __check_for_switch_to_b(bipbuf_t* me)
{
    if (me->size - me->a_end < me->a_start - me->b_end)
        me->b_inuse = 1;
}

/* TODO: DOCUMENT THESE TWO FUNCTIONS */
unsigned char *bipbuf_request(bipbuf_t* me, const int size)
{
    if (bipbuf_unused(me) < size)
        return 0;
    if (1 == me->b_inuse)
    {
        return (unsigned char *)me->data + me->b_end;
    }
    else
    {
        return (unsigned char *)me->data + me->a_end;
    }
}

int bipbuf_push(bipbuf_t* me, const int size)
{
    if (bipbuf_unused(me) < size)
        return 0;

    if (1 == me->b_inuse)
    {
        me->b_end += size;
    }
    else
    {
        me->a_end += size;
    }

    __check_for_switch_to_b(me);
    return size;
}

int bipbuf_offer(bipbuf_t* me, const unsigned char *data, const int size)
{
    /* not enough space */
    if (bipbuf_unused(me) < size)
        return 0;

    if (1 == me->b_inuse)
    {
        memcpy(me->data + me->b_end, data, size);
        me->b_end += size;
    }
    else
    {
        memcpy(me->data + me->a_end, data, size);
        me->a_end += size;
    }

    __check_for_switch_to_b(me);
    return size;
}

unsigned char *bipbuf_peek(const bipbuf_t* me, const unsigned int size)
{
    /* make sure we can actually peek at this data */
    if (me->size < me->a_start + size)
        return NULL;

    if (bipbuf_is_empty(me))
        return NULL;

    return (unsigned char *)me->data + me->a_start;
}

unsigned char *bipbuf_peek_all(const bipbuf_t* me, unsigned int *size)
{
    if (bipbuf_is_empty(me))
        return NULL;

    *size = me->a_end - me->a_start;
    return (unsigned char*)me->data + me->a_start;
}

unsigned char *bipbuf_poll(bipbuf_t* me, const unsigned int size)
{
    if (bipbuf_is_empty(me))
        return NULL;

    /* make sure we can actually poll this data */
    if (me->size < me->a_start + size)
        return NULL;

    void *end = me->data + me->a_start;
    me->a_start += size;

    /* we seem to be empty.. */
    if (me->a_start == me->a_end)
    {
        /* replace a with region b */
        if (1 == me->b_inuse)
        {
            me->a_start = 0;
            me->a_end = me->b_end;
            me->b_end = me->b_inuse = 0;
        }
        else
            /* safely move cursor back to the start because we are empty */
            me->a_start = me->a_end = 0;
    }

    __check_for_switch_to_b(me);
    return end;
}
