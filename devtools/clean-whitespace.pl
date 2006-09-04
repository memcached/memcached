#!/usr/bin/perl
use strict;
use FindBin qw($Bin);
chdir "$Bin/.." or die;
my @files = (glob("*.h"), glob("*.c"));
foreach my $f (@files) {
    open(my $fh, $f) or die;
    my $before = do { local $/; <$fh>; };
    close ($fh);
    my $after = $before;
    $after =~ s/\t/    /g;
    $after =~ s/\s+$//mg;
    next if $after eq $before;
    open(my $fh, ">$f") or die;
    print $fh $after;
    close($fh);
}
