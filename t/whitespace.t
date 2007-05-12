#!/usr/bin/perl
use strict;
use FindBin qw($Bin);
our @files;

BEGIN {
    chdir "$Bin/.." or die;
    @files = grep {! /^config.h$/ } (glob("*.h"), glob("*.c"), glob("*.ac"), "memcached.spec");
}
use Test::More tests => scalar(@files);

foreach my $f (@files) {
    open(my $fh, $f) or die;
    my $before = do { local $/; <$fh>; };
    close ($fh);
    my $after = $before;
    $after =~ s/\t/    /g;
    $after =~ s/ +$//mg;
    $after .= "\n" unless $after =~ /\n$/;
    ok ($after eq $before, "$f (see devtools/clean-whitespace.pl)");
}
