#!/usr/bin/perl
##########################################################
#
#		    Oleg Ponomarev
# Helsinki Institute for Information Technology
#
##########################################################
# 
# Executed by hipd after address changes on the interfaces
# It expects parameters in the environment variables: 
# IPS with space-separated list of ip addreses
# HIT with Host Identitity Tag 
# for example,
# IPS='192.168.187.1 2001:db8:140:220:215:60ff:fe9f:60c4'
# HIT='2001:1e:574e:2505:264a:b360:d8cc:1d75'
#
##########################################################

$CONFIG_PATH = "/etc/hip/nsupdate.conf";

# default values, please change in config
$HIT_TO_IP_ZONE = 'hit-to-ip.infrahip.net.';
$NSUPDATE_PATH = '|/usr/bin/nsupdate';

do $CONFIG_PATH;

use Net::IP qw/ip_is_ipv6 ip_is_ipv4/;

$env_IPS = $ENV{IPS};
$env_HIT = $ENV{HIT};

my $hit = new Net::IP($env_HIT) or die "\"$env_HIT\" does not look like HIT -- " . (Net::IP::Error());
$r = $hit->reverse_ip();

$r =~ /^(.+)\.ip6\.arpa\.$/ or die "\"$env_HIT\" does not look like HIT -- $r";

$rev_hit=$1;

open(NSUPDATE,$NSUPDATE_PATH) or die "Can't open $NSUPDATE_PATH";

# send update from HIT
# commented due to "request.c:887: REQUIRE(isc_sockaddr_pf(srcaddr) == isc_sockaddr_pf(destaddr)) failed"
# print NSUPDATE "local ${env_HIT}\n"; 

if ($SERVER ne '')
{
	print NSUPDATE "server $SERVER\n";
}

if (($KEY_NAME ne '') && ($KEY_SECRET ne ''))
{
	print NSUPDATE "key $KEY_NAME $KEY_SECRET\n";
}

print NSUPDATE <<_EOF1_;
update delete ${rev_hit}.hit-to-ip.infrahip.net
_EOF1_

@ips = split(/ /,$env_IPS);

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
