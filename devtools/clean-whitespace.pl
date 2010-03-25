#!/usr/bin/perl
use strict;
use FindBin qw($Bin);
chdir "$Bin/.." or die;
my @files = (glob("*.h"), glob("*.c"), glob("*.ac"), glob("./win32/*.c"), glob("./win32/*.h"), glob("./m4/*.m4"));

foreach my $f (@files) {
    open(my $fh, $f) or die;
    my $before = do { local $/; <$fh>; };
    close ($fh);
    my $after = $before;
    $after =~ s/\t/    /g;
    $after =~ s/ +$//mg;
    $after .= "\n" unless $after =~ /\n$/;
    next if $after eq $before;
    open(my $fh, ">$f") or die;
    print $fh $after;
    close($fh);
}
