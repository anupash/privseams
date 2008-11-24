#!/usr/bin/perl

use Net::IP qw/ip_is_ipv6 ip_is_ipv4/;

$env_IPS = $ENV{IPS};
$env_HIT = $ENV{HIT};

my $hit = new Net::IP($env_HIT) or die (Net::IP::Error());
$r = $hit->reverse_ip();

$r =~ /^(.+)\.ip6\.arpa\.$/ or die "Usage: $0 h:i:t";

$rev_hit=$1;

# key hit-to-ip.infrahip.net. Ousu6700S9sfYSL4UIKtvnxY4FKwYdgXrnEgDAu/rmUAoyBGFwGs0eY38KmYGLT1UbcL/O0igGFpm+NwGftdEQ==

open(NSUPDATE,">>/tmp/nsupdate.txt");
print NSUPDATE <<_EOF1_;
update delete ${rev_hit}.hit-to-ip.infrahip.net IN A
update delete ${rev_hit}.hit-to-ip.infrahip.net IN AAAA
_EOF1_


@ips = split(/\,/,$env_IPS);

foreach $ip (@ips)
{
	if (ip_is_ipv6($ip))
	{
		print NSUPDATE "update add ${rev_hit}.hit-to-ip.infrahip.net 60 IN AAAA $ip\n";
	}
 	elsif (ip_is_ipv4($ip))
 	{
		print NSUPDATE "update add ${rev_hit}.hit-to-ip.infrahip.net 60 IN A $ip\n";
	}
}

print NSUPDATE "send\n";
close(NSUPDATE);

exit $?

