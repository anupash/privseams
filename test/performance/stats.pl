#!/usr/bin/perl -w
#
# name:      stats.pl
# purpose:   generate statistics from a logfile encoded in {type,val} format
# usage:     see gethelp sub or run with no args
# version:   $Id: stats.pl,v 1.5 2003/10/14 15:50:31 krisu Exp $
# author:    miika@iki.fi
# licence:   GNU/GPL
#
# todo:
# - replace map_confidence with the corresponding perl module
#
### MODULES ##################################################################

use English;
use strict;
use Statistics::Distributions qw(udistr);


### GLOBAL VARIABLES #########################################################

# The $regexp matches type and the corresponding value according to the
# %regexp_order. The parentheses in the $regexp are used to pick up the type
# and value from the data input lines. If value occurs before type in the
# line, change the type to $2 and value to $1 in %regexp_order.
#
my $regexp       = 'hipd call type=(\S+):\s(\S+) secs';
my %regexp_order = ( 'type' => '$1', 'value' => '$2' );

my $confidence   = 0;  # confidence interval in procents

my %val          = (); # $value{type} contains a list of the values of "type"
my %avg          = (); # $avg{type} is the average of the values of "type"
my %std_dev      = (); # $std_dev{type} is the standard deviation of "type"
my %conf         = (); # the confidence interval pair calculated of the values

# filtered values, averages, standard deviations
#
my %filt_val     = ();
my %filt_avg     = ();
my %filt_std_dev = ();
my %filt_sum     = (); # e.g. $sum{'avg'} is the sum of all averages


# The input/output streams are read/written from these file descriptors.
#
my $inputfd      = \*STDIN;
my $outputfd     = \*STDOUT;

### MAIN PROGRAM #############################################################

# Check args.
#
die gethelp() unless getargs();

# Load values into %value. After this $value{type} contains a list of
# the corresponding values.
#
%val = read_values($inputfd, $regexp, \%regexp_order);

# Count averages and standard deviations of each type of value list.
#
foreach my $type (keys(%val)) {
    $avg{$type}     = average(@{ $val{$type} });
    $std_dev{$type} = standard_deviation($avg{$type}, @{ $val{$type} });
    push(@{ $conf{$type} }, confidence_interval($avg{$type},
						$std_dev{$type},
						$confidence));
}

# Filter the values that are not in the confidence interval.
#
foreach my $type (keys(%val)) {
    if ($confidence == 100) {
	# no values will be filtered
	push(@{ $filt_val{$type} }, @{ $val{$type} });
    } else { 
	push(@{ $filt_val{$type} }, filter(@{ $conf{$type} },
					   @{ $val{$type} }));
    }

    # Average/stddev cannot be calculated if there are no values left
    # (division by zero).
    if ($#{ @{ $filt_val{$type} } } != -1) {
	$filt_avg{$type}     = average(@{ $filt_val{$type} });
	$filt_std_dev{$type} = standard_deviation($filt_avg{$type},
						  @{ $filt_val{$type} });
    }
}

# Count the sums of average, deviations, etc
#
$filt_sum{'avg'} = 0;
$filt_sum{'std_dev'} = 0;
$filt_sum{'dropped'} = 0;
$filt_sum{'nbr'} = 0;
foreach my $type (keys(%filt_val)) {
    $filt_sum{'avg'}     += $filt_avg{$type} if (defined($filt_avg{$type}));
    $filt_sum{'std_dev'} += $filt_std_dev{$type}
    if (defined($filt_std_dev{$type}));
    $filt_sum{'dropped'} += $#{@{$val{$type}}} - $#{@{$filt_val{$type}}};
    $filt_sum{'nbr'}     += $#{@{$val{$type}}} + 1;
}

# Print the results.
#
print($outputfd "Filtered results:\ntype\tavg\tstd_dev\tdropped\tnbr\n");
foreach my $type (keys(%filt_val)) {
    my ($filt_avg, $filt_std_dev) = ($filt_avg{$type}, $filt_std_dev{$type});
    $filt_avg     = "N/A" unless (defined($filt_avg));
    $filt_std_dev = "N/A" unless (defined($filt_std_dev));
    print($outputfd
	  $type                                          . "\t" .
	  $filt_avg                                      . "\t" .
	  $filt_std_dev                                  . "\t" .
	  ($#{@{$val{$type}}} - $#{@{$filt_val{$type}}}) . "\t" .
	  ($#{@{$val{$type}}} + 1) . "\n");
}

# Print sums.
#
$filt_sum{'avg'}     = "N/A" if (!defined($filt_sum{'avg'}));
$filt_sum{'std_dev'} = "N/A" if (!defined($filt_sum{'std_dev'}));
print($outputfd "Sums:\n\t"  .
      $filt_sum{'avg'}       . "\t" .
      $filt_sum{'std_dev'}   . "\t" .
      $filt_sum{'dropped'}   . "\t" .
      $filt_sum{'nbr'}       . "\n");

### SUBROUTINES ##############################################################

# Purpose: Get the usage help
# Params:  None
# Returns: The formatted string of usage string
#
sub gethelp {
    return "Usage: stats <confidence_interval_in_procents>\n" .
	"The data to be analyzed is read from stdin.\n";
}

# Purpose: Get, check and parse the arguments given for the program
# Params:  None
# Returns: 1 if args were ok, else 0
# Depends: $ARGV, $confidence
#
sub getargs {
    my $ret = 1;

    if ($#ARGV != 0 || $ARGV[0] eq "-h") {
	$ret = 0;
    } else {
	if ($ARGV[0] >= 0 || $ARGV[0] <= 100) {
	    $confidence = $ARGV[0];
	} else {
	    print("Confidence value must be between [0..100]\n");
	    $ret = 0;
	}
    }

    return $ret;
}

# Purpose: Read the values for types from the filehandle 
# Params:  $inputfd        A filehandle where the input data will be read
#          $regexp         A regexp for catching type values
#          \%regexp_order  A refererence to the hash of the order of the
#                          type values
# Returns: Returns the hash of arrays of values (hash key = type of value)
#
sub read_values {
    my %value = ();
    my ($inputfd, $regexp) = (shift(@ARG), shift(@ARG));
    my %regexp_order = %{ shift(@ARG) };

    while (defined(my $line = <$inputfd>)) {
	$line =~ /$regexp/;
	push (@{ $value{eval($regexp_order{'type'})} },
	      eval($regexp_order{'value'}));
    }
    return %value;
}

# Purpose: Count the average of values.
# Params:  @value List of values
# Returns: The average of values
#
sub average {
    my @value = @ARG;
    return eval(join(" + ", @value)) / ($#value + 1);
}

# Purpose: Calculate standard deviation of the given values
# Params:  $avg  the average of @val
#          @val  the values
# Returns: 
#
sub standard_deviation {
    my $avg = shift(@ARG);
    my @val = @ARG;
    my $sum = 0;

    foreach my $val (@val) {
	my $delta = $val - $avg;
	$sum += $delta * $delta;
    }

    return sqrt($sum / ( $#val + 1));
}

# Purpose: map procents to the values into standard distribution table values.
# Params:  $procent a number between zero and 1
# Returns: a value from the standard distribution table
# Notes:   REPLACE WITH THE PERL MODULE
#
#sub map_confidence {
#    my $procent = $ARG[0];
#    # confidence values map procents to the standard distribution
#    my %conf_val  = ( .90 => 1.65, .95 => 1.96, .99 => 2.58,
#		      .999 => 3.29);
#    return $conf_val{$procent};
#}

# Purpose: Calculate confidence interval
# Params:  $avg      the average
#          $std_dev  standard deviation
#          $conf     confidence interval in procents [0..100]
# Returns: (lower, upper) confidence interval value pair
#
sub confidence_interval {
    my ($avg, $std_dev, $conf) = @ARG;
    my ($udist_val, $upper, $lower, $diff);

    $udist_val = (100 - (100 - $conf) / 2) / 100;
    $diff = abs(udistr($udist_val) * $std_dev);
    $lower = $avg - $diff;
    $upper = $avg + $diff;

    #die ("$lower $upper \n");

    return ($lower, $upper);
}

# Purpose: Filter off the values from a list that are not within the
#          given range
# Params:  $lower  Lower limit of the range
#          $upper  Upper limit of the range
#          @val    The values to be filtered
#
# Returns: The list of filtered values.
#
sub filter {
    my ($lower, $upper, @val) = @ARG;
    my @filtered_val = ();
    foreach my $val (@val) {
	push(@filtered_val, $val) if ($val >= $lower && $val <= $upper);
    }
    
    return @filtered_val;
}
