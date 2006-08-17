#!/usr/bin/perl -w

# Reads stdin and converts docbook comments to doxygen format

use English;
use strict;

while (defined(my $line = <>)) {
    $line =~ s/\s+\*\s+\@(\S+)\:\s+/\ \*\ \@param\ $1\ /;
    $line =~ s/\s+\*\s+Returns\:\s+/\ \*\ \@return\ /;
    $line =~ s/\/\*\s+XX\ TODO\:/\/\*\!\ \\todo/;
    $line =~ s/\/\*\s+TODO\:/\/\*\!\ \\todo/;
#    $line =~ s///;
#    $line =~ s///;
#    $line =~ s///;
    print "$line";
}
