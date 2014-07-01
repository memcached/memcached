#!/usr/bin/perl
# Issue #370 is a terrible bug has the same root reason as #260.
# In order to run this test(the code modify see the diff at the end for detail):
# * checkout version no higher than 1.4.20.
# * add code "if (expanding)sleep(1000);" to the function assoc_maintenance_thread, just before the first "item_lock_global();"
# * add code "sleep(2);" to the function do_item_alloc, before the evicted process(after this line:"else if ((it = slabs_alloc(ntotal, id)) == NULL)");
# * add code "sleep(3);" to the function item_get, just before the "return it;" line.
# * add code "assert(it->refcount<=1);" to the function do_item_alloc, before reset the refcount
# * modify the code "if (! expanding && hash_items > (hashsize(hashpower) * 3) / 2)" to "if (! expanding && hash_items > 1)", in function assoc_insert;
# * the key "Y_ORDER_225426358_02", "71912_yhd.serial.product.get_1.0_0" and "B920818_0" have the save hash value. it is important.
# Now it should cause an assert. Patches can be tested to fix it.

use strict;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

plan skip_all => "Higher probability to test #370 and #260 SHOULD under artificial conditions, read the test comment first plz.";
exit 0;
plan tests => 12;
# assuming max slab is 1M and max mem is 2M
my $server = new_memcached("-m 3");
my $sock = $server->sock;
my $sock2 = $server->new_sock;

# create a big value for the largest slab
my $max = 1024 * 1024;
my $big = 'x' x (1024 * 1024 - 250);

ok(length($big) > 512 * 1024);
ok(length($big) < 1024 * 1024);

my $key1 = "Y_ORDER_225426358_02";
my $key2 = "71912_yhd.serial.product.get_1.0_0";
my $key3 = "B920818_0";

# set the big value
my $len = length($big);

print $sock "set other_key 0 0 $len\r\n$big\r\n";
is(scalar <$sock>, "STORED\r\n", "stored other_key as first");
#mem_get_is($sock, "big", $big);

print $sock "set $key1 0 0 $len\r\n$big\r\n";
is(scalar <$sock>, "STORED\r\n", "stored $key1");
#mem_get_is($sock, "big", $big);

print $sock "set $key2 0 0 $len\r\n$big\r\n";
is(scalar <$sock>, "STORED\r\n", "stored $key2");
#mem_get_is($sock, "big", $big);


# now reach the max memory, but no evictions yet
my $stats = mem_stats($sock);
is($stats->{"evictions"}, "0", "no evictions to start");

#<STDIN>;

print $sock "set other_key2 0 0 $len\r\n$big\r\n";
is(scalar <$sock>, "STORED\r\n", "stored other_key2");

# some evictions should have happened
# hash expanding is happening
my $stats = mem_stats($sock);
my $evictions = int($stats->{"evictions"});
ok($evictions == 1, "some evictions happened");
my $evictions = int($stats->{"hash_is_expanding"});
ok($evictions == 1, "hash expanding happened");

# the first key1 value should be gone
mem_get_is($sock, "other_key", undef);

#set the $key1 again, 
# Now we reset the $key1's refcount to 1, then return for $key1 as a new item.
# the item is holding by the get $key2 thread.
# THIS asserts the memcached-debug binary.
print $sock "set test_key 0 0 $len\r\n$big\r\n";
sleep 2;
print $sock2 "get $key1\r\n";

is(scalar <$sock>, "STORED\r\n", "set test_key again");
ok(scalar <$sock2> == "$big\r\n", "get $key1");


=ps
output should like this
##########
[root@jason-2 memcached]# perl t/issue_370.t 
1..12
ok 1
ok 2
ok 3 - stored other_key as first
ok 4 - stored Y_ORDER_225426358_02
ok 5 - stored 71912_yhd.serial.product.get_1.0_0
ok 6 - no evictions to start
***exicted1 *hv=0x82dddc74,ref=2***
***exicted2*hv=0x82dddc74,ref=2***
ok 7 - stored other_key2
ok 8 - some evictions happened
ok 9 - hash expanding happened
**get1**hv=0x82dddc74,ref=0***
**get2**hv=0x82dddc74,ref=0***
ok 10 - other_key == <undef>
***exicted1 *hv=0xd994db22,ref=2***
**get1**hv=0xd994db22,ref=0***
**get2**hv=0xd994db22,ref=3***
***exicted2*hv=0xd994db22,ref=3***
ok 11 - set test_key again
ok 12 - get Y_ORDER_225426358_02
memcached-debug: items.c:233: item_free: Assertion `(it->it_flags & 1) == 0' failed.
[root@jason-2 memcached]# 

###################


#####code modification like this:
[root@jason-2 memcached]# git diff | cat
diff --git a/assoc.c b/assoc.c
index 5558be1..0984d48 100644
--- a/assoc.c
+++ b/assoc.c
@@ -167,7 +167,7 @@ int assoc_insert(item *it, const uint32_t hv) {
     }
 
     hash_items++;
-    if (! expanding && hash_items > (hashsize(hashpower) * 3) / 2) {
+    if (! expanding && hash_items > 1) {
         assoc_start_expand();
     }
 
@@ -208,6 +208,7 @@ static void *assoc_maintenance_thread(void *arg) {
 
         /* Lock the cache, and bulk move multiple buckets to the new
          * hash table. */
+       if (expanding)sleep(1000);
         item_lock_global();
         mutex_lock(&cache_lock);
 
diff --git a/items.c b/items.c
index 59f7427..be830a4 100644
--- a/items.c
+++ b/items.c
@@ -156,6 +156,9 @@ item *do_item_alloc(char *key, const size_t nkey, const int flags,
             /* Initialize the item block: */
             it->slabs_clsid = 0;
         } else if ((it = slabs_alloc(ntotal, id)) == NULL) {
+            printf("***exicted1 *hv=%#x,ref=%u***\n",hv,search->refcount);
+            sleep(5);
+            printf("***exicted2*hv=%#x,ref=%u***\n",hv,search->refcount);
             tried_alloc = 1;
             if (settings.evict_to_free == 0) {
                 itemstats[id].outofmemory++;
@@ -203,6 +206,7 @@ item *do_item_alloc(char *key, const size_t nkey, const int flags,
 
     assert(it->slabs_clsid == 0);
     assert(it != heads[id]);
+    assert(it->refcount<=1);
 
     /* Item initialization can happen outside of the lock; the item's already
      * been removed from the slab LRU.

diff --git a/thread.c b/thread.c
index ba56e5f..733274c 100644
--- a/thread.c
+++ b/thread.c
@@ -504,9 +510,12 @@ item *item_get(const char *key, const size_t nkey) {
     item *it;
     uint32_t hv;
     hv = hash(key, nkey);
+    printf("**get1**hv=%#x,ref=%u***\n",hv,0);
     item_lock(hv);
     it = do_item_get(key, nkey, hv);
     item_unlock(hv);
+    printf("**get2**hv=%#x,ref=%u***\n",hv,it?it->refcount:0);
+    sleep(8);
     return it;
 }
 
[root@jason-2 memcached]# 



=cut














