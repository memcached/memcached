# Memcached 1.4.17S

This is special flavour of memcached containing some changes for better performance and lower memory usage

## Better factor handling

- No longer slabs with different sizes and same perslab will be created, eg. before we could have: [ 3 slabs, item sizes = 350kb / 400kb / 480kb ] , with slab size=1M, they all end up with perslab = 2 After the change just one slab will be created. This will allow more variance in upper slab size distribution, so we can optimize more evenly using even small slab number (200), because slabs won't be wasted on same perslab items.

- You can now have several -f (factors) that'll be used evenly to calculate slab sizes, there's maximum of 10 factors which is defined as: FACTOR_MAX_COUNT 10

- Some more logic that'll prevent having incorrect slab sizes instead of throwing an error, eg. if there's 8 byte alignment, having factor of 1 will increase next slab size by 8 bytes

- Updated statistics to display all factors used

Optimal config to use for caching small items: -n8 -f1,1,1,1.05,1.12

Optimal config to use for caching larger items: -n20 -f1,1.05,1.18

## On-demand, fast eviction algorithm
This algo won't use linked lists, like previous version in 1.4.13S but instead will scan up to X items from each SLAB memory to look for valid items. This allows us to have nearly O(1) experience, like other memcached functions, when properly configured, and prevents locking for several milliseconds during manual evictions.

Scan position and memory block number is saved so we can split otherwise fairly long operation to several lock-friendly sub-ops, making use of fact that each item is starting on FIXED position ( slab start + item_no * item_size )


---

# Memcached

## Dependencies

* libevent, http://www.monkey.org/~provos/libevent/ (libevent-dev)

## Environment

### Linux

If using Linux, you need a kernel with epoll.  Sure, libevent will
work with normal select, but it sucks.

epoll isn't in Linux 2.4, but there's a backport at:

    http://www.xmailserver.org/linux-patches/nio-improve.html

You want the epoll-lt patch (level-triggered).

### Mac OS X

If you're using MacOS, you'll want libevent 1.1 or higher to deal with
a kqueue bug.

Also, be warned that the -k (mlockall) option to memcached might be
dangerous when using a large cache.  Just make sure the memcached machines
don't swap.  memcached does non-blocking network I/O, but not disk.  (it
should never go to disk, or you've lost the whole point of it)

## Website

* http://www.memcached.org

## Contributing

Want to contribute?  Up-to-date pointers should be at:

* http://contributing.appspot.com/memcached
