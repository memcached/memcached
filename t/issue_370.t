#!/usr/bin/perl
# Issue #370 is a terrible bug has the same root reason as #260.
# In order to run this test:
# * checkout version no higher than 1.4.20.
# * add code "if (expanding)sleep(1000);" to the function assoc_maintenance_thread, just before the first "item_lock_global();"
# * add code "sleep(2);" to the function do_item_alloc, before the evicted process(after this line:"else if ((it = slabs_alloc(ntotal, id)) == NULL)");
# * add code "sleep(3);" to the function item_get, just before the "return it;" line.
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
plan tests => 11;
# assuming max slab is 1M and max mem is 2M
my $server = new_memcached("-m 2");
my $sock = $server->sock;
my $sock2 = $server->sock;

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
print $sock "set $key1 0 0 $len\r\n$big\r\n";
is(scalar <$sock>, "STORED\r\n", "stored $key1");
#mem_get_is($sock, "big", $big);

print $sock "set $key2 0 0 $len\r\n$big\r\n";
is(scalar <$sock>, "STORED\r\n", "stored $key2");
#mem_get_is($sock, "big", $big);

# nwo reach the max memory, but no evictions yet
my $stats = mem_stats($sock);
is($stats->{"evictions"}, "0", "no evictions to start");

print $sock "set $key3 0 0 $len\r\n$big\r\n";
is(scalar <$sock>, "STORED\r\n", "stored $key3");

# some evictions should have happened
# hash expanding is happening
my $stats = mem_stats($sock);
my $evictions = int($stats->{"evictions"});
ok($evictions == 1, "some evictions happened");
my $evictions = int($stats->{"hash_is_expanding"});
ok($evictions == 1, "hash expanding happened");

# the first key1 value should be gone
mem_get_is($sock, "$key1", undef);

#set the $key1 again, 
# Now we reset the $key2's refcount to 1, then return for $key1 as a new item.
# the item is holding by the get $key2 thread.
# THIS asserts the memcached-debug binary.
print $sock "set $key1 0 0 $len\r\n$big\r\n";
print $sock2 "get $key2\r\n";

is(scalar <$sock>, "STORED\r\n", "set $key1 again");
ok(scalar <$sock2> == "$big\r\n", "get $key2");


=ps
output should like this
##########
[root@jason-2 memcached]# perl t/issue_370.t
1..11
ok 1
ok 2
ok 3 - stored Y_ORDER_225426358_02
ok 4 - stored 71912_yhd.serial.product.get_1.0_0
ok 5 - no evictions to start
ok 6 - stored B920818_0
ok 7 - some evictions happened
ok 8 - hash expanding happened
ok 9 - Y_ORDER_225426358_02 == <undef>
ok 10 - set Y_ORDER_225426358_02 again
ok 11 - get 71912_yhd.serial.product.get_1.0_0
SIGINT handled.
###################


#####code modification like this:
[root@jason-2 memcached]# git diff
diff --git a/assoc.c b/assoc.c
index 5558be1..84431f7 100644
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
+        if (expanding)sleep(1000);
         item_lock_global();
         mutex_lock(&cache_lock);
 
diff --git a/items.c b/items.c
index 59f7427..ef1e097 100644
--- a/items.c
+++ b/items.c
@@ -156,6 +156,7 @@ item *do_item_alloc(char *key, const size_t nkey, const int 
             /* Initialize the item block: */
             it->slabs_clsid = 0;
         } else if ((it = slabs_alloc(ntotal, id)) == NULL) {
+            sleep(2);
             tried_alloc = 1;
             if (settings.evict_to_free == 0) {
                 itemstats[id].outofmemory++;
diff --git a/thread.c b/thread.c
index ba56e5f..bf103e1 100644
--- a/thread.c
+++ b/thread.c
@@ -507,6 +507,7 @@ item *item_get(const char *key, const size_t nkey) {
     item_lock(hv);
     it = do_item_get(key, nkey, hv);
     item_unlock(hv);
+    sleep(3);
     return it;
 }
 
[root@jason-2 memcached]#

=cut














