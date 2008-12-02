#!/usr/bin/perl
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
use strict;

my $CONFIG_PATH = "/etc/hip/nsupdate.conf";

# default values, please change in /etc/hip/nsupdate.conf 
my $HIT_TO_IP_ZONE = 'hit-to-ip.infrahip.net.';
my $SERVER = '';
my $KEY_NAME = '';
my $KEY_SECRET = '';

do $CONFIG_PATH;

use Net::DNS;
use Net::IP qw/ip_is_ipv6 ip_is_ipv4/;
use Sys::Syslog;

openlog('nsupdate.pl', 'ndelay,pid', 'local6');

my $env_IPS = $ENV{IPS};
my $env_HIT = $ENV{HIT};

unless ($env_HIT) {
	log_and_die("HIT environment variable is empty");
}

unless ($env_IPS) {
	log_error("warning IPS environment variable is empty");
	$env_IPS='';
}

my $res = Net::DNS::Resolver->new;

log_debug("Updating records in ${HIT_TO_IP_ZONE}");

my $server;
my @server_ips;
if ($SERVER) {
	$server = $SERVER;
	log_debug("Using $server from config");

	if (ip_is_ipv6($server)) {
		log_debug("which is ipv6 address");
		@server_ips = ($server);
		goto HAVE_SERVER_IPS;
	} elsif (ip_is_ipv4($server)) {		
		log_debug("which is ipv4 address");
		@server_ips = ($server);
		goto HAVE_SERVER_IPS;
	}
} else {
	$server = find_soa($HIT_TO_IP_ZONE, $res);
	log_debug("Using $server from SOA");
}

# we don't put symbolic name to Resolver->nameservers because it will not use AAAA then
@server_ips = find_server_addresses($server, $res);
log_debug("Resolved nameserver to " . join(',', @server_ips));

HAVE_SERVER_IPS: $res->nameservers(@server_ips);

my $update = prepare_update($env_HIT, $env_IPS);

if ($KEY_NAME) {
	unless ($KEY_SECRET) {
		log_and_and('KEY_NAME is defined, but KEY_SECRET is empty');
	}
	log_debug("Signing using $KEY_NAME");
	$update->sign_tsig($KEY_NAME, $KEY_SECRET);
}

log_debug("Using $env_HIT as local address");
$res->srcaddr($env_HIT);

send_update($update, $res);

exit 0;
####################################################################################################
sub find_soa
{
	my $zone = $_[0];
	my $res = $_[1];
	my $query = $res->query($zone, "SOA");

	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "SOA");
			return $rr->mname;
        	}
		log_and_die("SOA for $zone not found in the answer: " . $query->print());
	} else {
		log_and_die("SOA for $zone not found: " . $res->errorstring);
	}
}

####################################################################################################
sub find_server_addresses
{
	my $server = $_[0];
	my $res = $_[1];
	my $ip;

	my @addresses;

	my $query = $res->query($server, "AAAA");
	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "AAAA");
			push @addresses, $rr->address();
        	}
		return @addresses;
	}

	$query = $res->query($server, "A");
	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "A");
			push @addresses, $rr->address();
        	}
		return @addresses;
	} else {
		log_and_die("address of $server not found: " . $res->errorstring);
	}
}

####################################################################################################
sub prepare_update
{
	my $hit = new Net::IP($_[0]);
	my @ips = split(/\s/,$_[1]);

	my $r = $hit->reverse_ip();
	$r =~ /^(.+)\.ip6\.arpa\.$/ or log_and_die("\"$env_HIT\" does not look like HIT -- $r");
	my $rev_hit=$1;

	my $update = Net::DNS::Update->new($HIT_TO_IP_ZONE);

	$update->push(update => rr_del("${rev_hit}.${HIT_TO_IP_ZONE}."));

	foreach my $ip (@ips) {
        	if (ip_is_ipv6($ip)) {
			$update->push(update => rr_add("${rev_hit}.${HIT_TO_IP_ZONE} 1 AAAA $ip"));
		} elsif (ip_is_ipv4($ip)) {			
			$update->push(update => rr_add("${rev_hit}.${HIT_TO_IP_ZONE} 1 A $ip"));
		} else {
			log_error("Don't know how to add $ip");
		}
        }

	return $update;
}

####################################################################################################
sub send_update
{
	my $update = $_[0];
	my $res = $_[1];

	my $reply = $res->send($update);

        if ($reply) {
            if ($reply->header->rcode eq 'NOERROR') {
                log_debug("Update succeeded");
            } else {
                log_error('Update failed: ' . $reply->header->rcode);
            }
        } else {
            log_error('Update failed: ' . $res->errorstring);
        }
}

####################################################################################################
sub log_debug
{
	my $message = $_[0];
	syslog('debug', $message);
}

sub log_error
{
	my $message = $_[0];
	syslog('err', $message);
}

sub log_and_die
{
	my $message = $_[0];
	log_error($message);
	die $message;
}
