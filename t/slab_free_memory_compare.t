#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 111;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;
#######################################################
#Test the release memory feature by setting  random expire, random value length.
#
print "memcached1 disable release memory function, while memcache2 enable release memory function.\n";
my $server1 = new_memcached('-m 32 -I 128k -o slab_reassign,lru_crawler,slab_automove=1,release_mem_sleep=1,release_mem_start=60,release_mem_stop=90,lru_crawler_interval=5');
my $server2 = new_memcached('-m 32 -I 128k -o slab_reassign,lru_crawler,slab_automove=3,release_mem_sleep=1,release_mem_start=60,release_mem_stop=90,lru_crawler_interval=5');

my $sock1 = $server1->sock;
my $sock2 = $server2->sock;
my $evict1_old=0;
my $evict2_old=0;
# test loop number.
my $loop_cnt=100000;
while($loop_cnt--){
 my $rd_ttl=int(rand()*100+1);
 #ramdom value len
 my $rd_len=int(rand()*10000+1);
 my $data = 'y' x $rd_len;  

 #print "rd_ttl=$rd_ttl,rd_len=$rd_len \n";
 print $sock1 "set ifoo$loop_cnt 0 $rd_ttl $rd_len\r\n$data\r\n";
 scalar <$sock1>;
 print $sock2 "set ifoo$loop_cnt 0 $rd_ttl $rd_len\r\n$data\r\n";
 scalar <$sock2>;
 #display info.
 if ($loop_cnt%500==0){
  my $slabs1 = mem_stats($sock1, "slabs");
  my $total_mem1=$slabs1->{"total_malloced"};
  my $slabs2 = mem_stats($sock2, "slabs");
  my $total_mem2=$slabs2->{"total_malloced"};
  my $total_diff=int(($total_mem1-$total_mem2)/1000);
 
  my $stats1 = mem_stats($sock1);
  my $pid1 = $stats1->{pid};
  my $mem1=int(`ps -p $pid1 -orss= `);
  my $stats2 = mem_stats($sock2);
  my $pid2 = $stats2->{pid};
  my $mem2=int(`ps -p $pid2 -orss= `);
  my $release_mem = $mem1-$mem2;

  my $evict1 = int($stats1->{evictions});
  my $evict2 = int($stats2->{evictions});
  my $evict_diff = ($evict1-$evict1_old) - ($evict2-$evict2_old);
  my $evict1_incr = ($evict1-$evict1_old);
  $evict1_old = $evict1;
  $evict2_old = $evict2;

 print "total_mem1=$total_mem1 B,total_mem2=$total_mem2 B,diff=$total_diff kB,evict1_incr=$evict1_incr,evict_diff=$evict_diff,sys_mem1=$mem1 kB,sys_mem2=$mem2 kB,release sys_memory:$release_mem kB\n";
  #sleep 1;
 }
#<STDIN>;

}
