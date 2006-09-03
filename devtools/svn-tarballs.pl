#!/usr/bin/perl

use strict;
use FindBin qw($Bin);

my %branch = (
              '1.2.x' => "http://code.sixapart.com/svn/memcached/trunk/server",
              '1.1.x' => "http://code.sixapart.com/svn/memcached/branches/memcached-1.1.x",
              );

foreach my $b (keys %branch) {
    chdir $Bin or die;
    my $url = $branch{$b};
    my $out = `svn info $b`;
    unless ($out =~ /^URL: (.+)/m && $1 eq $url) {
        system("rm -rf $b");
        system("svn", "co", $url, $b)
            and die "Failed to checkout $url\n";
    } else {
        chdir "$Bin/$b" or die;
        system("svn up") and die "Failed to svn up";
    }

    chdir "$Bin/$b" or die;
    $out = `svn info .`;

    my ($maxrev) = $out =~ /^Last Changed Rev: (\d+)/m
        or die "No max rev?";

    print "$b = $maxrev\n";
    my $distfile = "memcached-$b-svn$maxrev.tar.gz";
    next if -f $distfile && -s _;

    open(my $fh, "configure.ac") or die "no configure.ac in $b?";
    my $ac = do { local $/; <$fh>; };
    close($fh);
    $ac =~ s!AC_INIT\(memcached,.+?\)!AC_INIT(memcached, $b-svn$maxrev, brad\@danga.com)!
        or die "Failed to replace";
    open (my $fh, ">configure.ac") or die "failed to write configure.ac writeable: $!";
    print $fh $ac;
    close ($fh);

    system("./autogen.sh") and die "Autogen failed.  Missing autotools?";
    system("./configure") and die "configure failed";
    system("make dist") and die "make dist failed";
    die "Failed to make dist $distfile." unless -s $distfile;
}


