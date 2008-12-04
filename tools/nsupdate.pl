#!/usr/bin/perl
##########################################################
# 
# Executed by hipd after address changes
#
# It expects parameters in the environment variables: 
# IPS with space-separated list of ip addreses
# HIT with Host Identitity Tag 
# for example,
# IPS='192.168.187.1 2001:db8:140:220:215:60ff:fe9f:60c4'
# HIT='2001:1e:574e:2505:264a:b360:d8cc:1d75'
#
# update reverse zone if UPDATE_REVERSE variable is set
##########################################################
use strict;

my $CONFIG_PATH = "/etc/hip/nsupdate.conf";

##########################################################
# default values, please change in /etc/hip/nsupdate.conf 
our $DEBUG = 0;

our $HIT_TO_IP_ZONE = 'hit-to-ip.infrahip.net.';
our $HIT_TO_IP_SERVER = '';
our $HIT_TO_IP_KEY_NAME = '';
our $HIT_TO_IP_KEY_SECRET = '';
our $HIT_TO_IP_TTL = 1;

our $REVERSE_ZONE = '1.0.0.1.0.0.2.ip6.arpa.';
our $REVERSE_SERVER = 'ptr-soa-hit.infrahip.net.'; # SOA for 1.0.0.1.0.0.2.ip6.arpa. is dns1.icann.org. now
our $REVERSE_KEY_NAME = '';
our $REVERSE_KEY_SECRET = '';
our $REVERSE_TTL = 86400;
our $REVERSE_HOSTNAME = '';
##########################################################

# Read configuration
do $CONFIG_PATH;

use Net::DNS;
use Net::IP qw/ip_is_ipv6 ip_is_ipv4/;
use Sys::Syslog;
use Sys::Hostname;

openlog('nsupdate.pl', 'ndelay,pid', 'local6');

my $env_HIT = $ENV{HIT};
my $env_IPS = $ENV{IPS};
my $env_UPDATE_REVERSE = $ENV{UPDATE_REVERSE};

unless ($env_HIT) {log_and_die("HIT environment variable is empty");}

# globally used resolver
my $RES = Net::DNS::Resolver->new;

if ($env_IPS) {update_hit_to_ip($env_HIT, $env_IPS);}

$RES = Net::DNS::Resolver->new;

if ($env_UPDATE_REVERSE) {
	unless ($REVERSE_HOSTNAME) { $REVERSE_HOSTNAME = hostname(); }
	update_reverse($env_HIT, $REVERSE_HOSTNAME);
}

exit 0;

####################################################################################################
sub update_hit_to_ip
{
	my $hit = $_[0];
	my $ips = $_[1];

	$RES->nameservers(nameservers($HIT_TO_IP_ZONE, $HIT_TO_IP_SERVER));

	my $update = prepare_hit_to_ip_update($hit, $ips);

	sign_update($update, $HIT_TO_IP_KEY_NAME, $HIT_TO_IP_KEY_SECRET);

	send_update_from_hit($update, $hit);
}

####################################################################################################
sub prepare_hit_to_ip_update
{
	my $rev_hit = reverse_hit($_[0]);
	my @ips = split(/\s/,$_[1]);

	my $update = Net::DNS::Update->new($HIT_TO_IP_ZONE);

	$update->push(update => rr_del("${rev_hit}.${HIT_TO_IP_ZONE}"));

	foreach my $ip (@ips) {
        	if (ip_is_ipv6($ip)) {
			$update->push(update => rr_add("${rev_hit}.${HIT_TO_IP_ZONE} ${HIT_TO_IP_TTL} AAAA $ip"));
		} elsif (ip_is_ipv4($ip)) {			
			$update->push(update => rr_add("${rev_hit}.${HIT_TO_IP_ZONE} ${HIT_TO_IP_TTL} A $ip"));
		} else {
			log_error("Don't know how to add $ip");
		}
        }

	return $update;
}

####################################################################################################
sub update_reverse
{
	my $hit = $_[0];
	my $hostname = $_[1];

	log_debug("Desired reverse: $hostname");
	my $rev_hit = reverse_hit($hit);

	unless ($rev_hit =~ /(.+)\.1\.0\.0\.1\.0\.0\.2$/) {log_and_die("$rev_hit does not end with ORCHID prefix");}
	my $rev_hit_without_orchid = $1;

	my @ptrs = find_ptrs($rev_hit_without_orchid);
	
	log_debug("Found reverse: " . join(',',@ptrs));

# Check if it already contains desired PTR 
	if (grep {$_ eq $hostname} @ptrs) {log_debug("No reverse update needed");return;}

	$RES->nameservers(nameservers($REVERSE_ZONE, $REVERSE_SERVER));

	my $update = prepare_reverse_update($rev_hit_without_orchid, $hostname);

	sign_update($update, $REVERSE_KEY_NAME, $REVERSE_KEY_SECRET);

	send_update_from_hit($update, $hit);
}

####################################################################################################
sub prepare_reverse_update
{
	my $rev_hit_without_orchid = $_[0];
	my $hostname = $_[1];

	my $update = Net::DNS::Update->new($REVERSE_ZONE);

	unless ($hostname =~ /\.$/) {$hostname .= ".";}

	$update->push(update => rr_del("${rev_hit_without_orchid}.${REVERSE_ZONE}"));
	$update->push(update => rr_add("${rev_hit_without_orchid}.${REVERSE_ZONE} ${REVERSE_TTL} PTR ${hostname}"));

	return $update;
}

####################################################################################################
sub nameservers
{
	my $zone = $_[0];
	my $server = $_[1];

	log_debug("Updating records in $zone");

	if ($server) {
		log_debug("Using $server from config");
		if (ip_is_ipv6($server)) {
			log_debug("which is ipv6 address");
			return ($server);
		} elsif (ip_is_ipv4($server)) {		
			log_debug("which is ipv4 address");
			return ($server);
		}
	} else {
		$server = find_soa($zone);
		log_debug("Using $server from SOA");
	}

	# we can't put symbolic name to Resolver->nameservers because it would not use AAAA then
	my @server_ips = find_server_addresses($server);
	log_debug("Resolved nameserver to " . join(',', @server_ips));

	return @server_ips;
}

####################################################################################################
sub find_soa
{
	my $zone = $_[0];

	my $query = $RES->query($zone, "SOA");

	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "SOA");
			if ($rr->mname =~ /icann\.org/) {log_and_die("Will not send update to $rr->mname");}
			return $rr->mname;
        	}
		log_and_die("SOA for $zone not found in the answer: " . $query->print());
	} else {
		log_and_die("SOA for $zone not found: " . $RES->errorstring);
	}
}

####################################################################################################
sub find_server_addresses
{
	my $server = $_[0];
	my $ip;

	my @addresses;

	my $query = $RES->query($server, "AAAA");
	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "AAAA");
			push @addresses, $rr->address();
        	}
		return @addresses;
	}

	$query = $RES->query($server, "A");
	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "A");
			push @addresses, $rr->address();
        	}
		return @addresses;
	} else {
		log_and_die("address of $server not found: " . $RES->errorstring);
	}
}

####################################################################################################
sub find_ptrs
{
	my $rev_hit_without_orchid = $_[0];

	if ($REVERSE_SERVER) {
		$RES->nameservers(find_server_addresses($REVERSE_SERVER));
	}

	my $query = $RES->query($rev_hit_without_orchid . "." . $REVERSE_ZONE , "PTR");

	my @ptrs;

	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "PTR");
			push @ptrs, $rr->ptrdname();
        	}
	}

	return @ptrs;
}

####################################################################################################
sub reverse_hit
{
 my $hit = new Net::IP($_[0]);
 my $r = $hit->reverse_ip();
 $r =~ /^(.+)\.ip6\.arpa\.$/ or log_and_die("\"$env_HIT\" does not look like HIT -- $r");
 return $1;
}

####################################################################################################
sub sign_update
{
	my $update = $_[0];
	my $key_name = $_[1];
	my $key_secret = $_[2];
	
	if ($key_name) {
		unless ($key_secret) {log_and_and('KEY_NAME is defined, but KEY_SECRET is empty');}
		log_debug("Signing using $key_name");
		$update->sign_tsig($key_name, $key_secret);
	}
}

####################################################################################################
sub send_update_from_hit
{
	my $update = $_[0];
	my $hit = $_[1];

	log_debug("Using $hit as local address");
	$RES->srcaddr($hit);

	my $reply = $RES->send($update);

        if ($reply) {
            if ($reply->header->rcode eq 'NOERROR') {
                log_debug("Update succeeded");
            } else {
                log_error('Update failed: ' . $reply->header->rcode);
            }
        } else {
            log_error('Update failed: ' . $RES->errorstring);
        }
}

####################################################################################################
sub log_debug
{
	my $message = $_[0];
	if ($DEBUG) {print $message, "\n";}
	syslog('debug', $message);
}

sub log_error
{
	my $message = $_[0];
	if ($DEBUG) {print $message, "\n";}
	syslog('err', $message);
}

sub log_and_die
{
	my $message = $_[0];
	log_error($message);
	die $message;
}
