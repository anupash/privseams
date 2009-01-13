#! /usr/bin/env python

# HIP namelook up daemon for /etc/hip/hosts and DNS and Bamboo servers
#
# Usage: Basic usage without any command line options.
#        See getopt() for the options.
#
# Working test cases with hipdnsproxy
# - Interoperates with libc and dnsmasq
# - Resolvconf(on/off) + dnsmasq (on/off)
#    - initial look up (check HIP and non-hip look up)
#      - check that ctrl+c restores /etc/resolv.conf
#    - change access network (check HIP and non-hip look up)
#      - check that ctrl+c restores /etc/resolv.conf
# - Watch out for cached entries! Restart dnmasq and hipdnsproxy after
#   each test.
# - Test name resolution with following methods:
#   - Non-HIP records
#   - Hostname to HIT resolution
#     - HITs and LSIs from /etc/hip/hosts
#     - HI records from DNS
#     - HITs from Bamboo via hipd
#   - PTR records: maps HITs to hostnames from /etc/hip/hosts
#
# Actions to resolv.conf files and dnsproxy hooking:
# - Dnsmasq=on, revolvconf=on: only hooks dnsmasq
# - Dnsmasq=off, revolvconf=on: rewrites /etc/resolvconf/run/resolv.conf
# - Dnsmasq=on, revolvconf=off: hooks dnsmasq and rewrites /etc/resolv.conf
# - Dnsmasq=off, revolvconf=off: rewrites /etc/resolv.conf
#
# TBD:
# - make the code look more like object oriented
# - the use of alternative (multiple) dns servers
# - implement TTLs for cache
#   - applicable to HITs, LSIs and IP addresses
#   - host files: forever (purged when the file is changed)
#   - dns records: follow DNS TTL
# - bind to ::1, not 127.0.0.1 (setsockopt blah blah)
# - remove hardcoded addresses from ifconfig commands
# - "dig dsfds" takes too long with dnsproxy
# - hip_lookup is doing a qtype=255 search; the result of this
#   could be used instead of doing look up redundantly in
#   bypass

import sys
import getopt
import os
import stat
import time
import util
import socket
import DNS
import pyip6
import binascii
import hosts
import re
import signal
import syslog
import popen2
import fileinput

def usage(utyp, *msg):
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

path = os.environ.get('PATH',None)
if path != None:
    path = path.split(':')
else:
    path = []

# Done: forking affects this. Fixed in forkme
myid = '%d-%d' % (time.time(),os.getpid())

class ResolvConfError(Exception):
    pass

class Logger:
    def __init__(self):
        self.wrfun = sys.stdout.write
        self.flfun = sys.stdout.flush
        return
    def wrsyslog(self,s):
        syslog.syslog(s)
        return
    def setsyslog(self):
        syslog.openlog('dnsproxy',syslog.LOG_PID)
        self.wrfun = self.wrsyslog
        self.flfun = None
        return
    def flush(self):
        return
    def write(self,s):
        self.wrfun(s)
        if self.flfun: self.flfun()
        return

class ResolvConf:
    re_nameserver = re.compile(r'nameserver\s+(\S+)$')
    def is_resolvconf_in_use(self):
        return self.use_resolvconf
            
    def guess_resolvconf(self):
        if self.use_dnsmasq_hook and self.use_resolvconf:
            return self.dnsmasq_resolv
        elif self.use_resolvconf:
            return self.resolvconf_run
        else:
            return '/etc/resolv.conf'

    def __init__(self, alt_port = 0, filetowatch = None):
	self.dnsmasq_initd_script = '/etc/init.d/dnsmasq'
 	if os.path.exists('/etc/redhat-release'):
		self.distro = 'redhat'
		self.rh_before = '# See how we were called.'
		self.rh_inject = '. /etc/sysconfig/dnsmasq # Added by hipdnsproxy'
	elif os.path.exists('/etc/debian_version'):
		self.distro = 'debian'
	else:
		self.distro = 'unknown'

	if self.distro == 'redhat':
	        self.dnsmasq_defaults = '/etc/sysconfig/dnsmasq'
		if not os.path.exists(self.dnsmasq_defaults):
			open(self.dnsmasq_defaults, 'w').close()
	else:
	        self.dnsmasq_defaults = '/etc/default/dnsmasq'

        self.dnsmasq_defaults_backup = self.dnsmasq_defaults + '.backup.hipdnsproxy'

        if (os.path.isdir('/etc/resolvconf/.') and
            os.path.exists('/sbin/resolvconf') and
            os.path.exists('/etc/resolvconf/run/resolv.conf')):
            self.use_resolvconf = True
        else:
            self.use_resolvconf = False

        if (alt_port > 0 and
            os.path.exists(self.dnsmasq_defaults)):
            self.use_dnsmasq_hook = True
        else:
            self.use_dnsmasq_hook = False

        self.alt_port = alt_port
        self.dnsmasq_resolv = '/var/run/dnsmasq/resolv.conf'
        self.resolvconf_run = '/etc/resolvconf/run/resolv.conf'
        if self.use_resolvconf:
            self.resolvconf_towrite = '/etc/resolvconf/run/resolv.conf'
        else:
            self.resolvconf_towrite = '/etc/resolv.conf'
	if self.distro == 'redhat':
	        self.dnsmasq_hook = 'OPTIONS+="--no-hosts --no-resolv --server=127.0.0.53#' + str(self.alt_port) + '"\n'
	else:
        	self.dnsmasq_hook = 'DNSMASQ_OPTS="--no-hosts --no-resolv --server=127.0.0.53#' + str(self.alt_port) + '"\n'
        self.dnsmasq_restart = self.dnsmasq_initd_script + ' restart'
        if filetowatch == None:
            self.filetowatch = self.guess_resolvconf()
        self.resolvconf_orig = self.filetowatch
        self.old_rc_mtime = os.stat(self.filetowatch).st_mtime
        self.resolvconf_bkname = '%s-%s' % (self.resolvconf_towrite,myid)
        return

    def get_dnsmasq_hook_status(self):
        return self.use_dnsmasq_hook;

    def reread_old_rc(self):
        d = {}
        self.resolvconfd = d
        f = file(self.filetowatch)
        for l in f.xreadlines():
            l = l.strip()
            if not d.has_key('nameserver'):
                r1 = self.re_nameserver.match(l)
                if r1:
                    d['nameserver'] = r1.group(1)
        return d
    def old_has_changed(self):
        old_rc_mtime = os.stat(self.filetowatch).st_mtime
        if old_rc_mtime != self.old_rc_mtime:
            self.reread_old_rc()
            self.old_rc_mtime = old_rc_mtime
            return 1
        else:
            return 0
    def save_resolvconf(self):
        if self.use_dnsmasq_hook:
	    if os.path.exists(self.dnsmasq_defaults):
                os.rename(self.dnsmasq_defaults, 
                          self.dnsmasq_defaults_backup)
            dmd = file(self.dnsmasq_defaults, 'w')
            dmd.write(self.dnsmasq_hook)
            dmd.close()
	    if self.distro == 'redhat':
		for line in fileinput.input(self.dnsmasq_initd_script, inplace=1):
			if line.find(self.rh_before) == 0:
				print self.rh_inject
			print line,
            os.system(self.dnsmasq_restart)
        if not (self.use_dnsmasq_hook and self.use_resolvconf):
            os.link(self.resolvconf_towrite,self.resolvconf_bkname)
        return

    def restore_resolvconf(self):
        if self.use_dnsmasq_hook:
            if os.path.exists(self.dnsmasq_defaults_backup):
              os.rename(self.dnsmasq_defaults_backup,
                        self.dnsmasq_defaults)
	    if self.distro == 'redhat':
		for line in fileinput.input(self.dnsmasq_initd_script, inplace=1):
			if line.find(self.rh_inject) == -1:
				print line,
            os.system(self.dnsmasq_restart)
        if not (self.use_dnsmasq_hook and self.use_resolvconf):
            os.rename(self.resolvconf_bkname, self.resolvconf_towrite)

        return

    def write(self,params):
        if (self.use_dnsmasq_hook and self.use_resolvconf):
            return

        keys = params.keys()
        keys.sort()
        tmp = '%s.tmp-%s' % (self.resolvconf_towrite,myid)
        tf = file(tmp,'w')
        tf.write('# This is written by dnsproxy.py\n')
        for k in keys:
            v = params.get(k)
            if type(v) == type(''):
                v = (v,)
            for v2 in v:
                tf.write('%-10s %s\n' % (k,v2))
        tf.close()
        os.rename(tmp,self.resolvconf_towrite)
        self.old_rc_mtime = os.stat(self.filetowatch).st_mtime

    def overwrite_resolv_conf(self):
        tmp = '%s.tmp-%s' % (self.resolvconf_towrite,myid)
        f1 = file(self.resolvconf_towrite,'r')
        f2 = file(tmp,'w')
        while 1:
            d = f1.read(16384)
            if not d:
                break
            f2.write(d)
        f1.close()
        f2.close()
        os.rename(tmp,self.resolvconf_towrite)

    def start(self):
        self.save_resolvconf()
        if not (self.use_dnsmasq_hook and self.use_resolvconf):
            self.overwrite_resolv_conf()

    def restart(self):
        if not (self.use_dnsmasq_hook and self.use_resolvconf):
            self.overwrite_resolv_conf()
            #if os.path.exists(self.resolvconf_bkname):
            #    os.remove(self.resolvconf_bkname)
        self.old_rc_mtime = os.stat(self.filetowatch).st_mtime

    def stop(self):
        self.restore_resolvconf()
	os.system("ifconfig lo:53 down")

class Global:
    default_hiphosts = "/etc/hip/hosts"
    default_hosts = "/etc/hosts"
    re_nameserver = re.compile(r'nameserver\s+(\S+)$')
    def __init__(gp):
        gp.resolv_conf = '/etc/resolv.conf'
        gp.hostsnames = []
	gp.server_ip = None
	gp.server_port = None
	gp.bind_ip = None
	gp.bind_port = None
        gp.bind_alt_port = None
        gp.use_alt_port = False
        gp.fork = False
        gp.pidfile = '/var/run/hipdnsproxy.pid'
        gp.kill = False
        gp.fout = sys.stdout
        gp.app_timeout = 1
        gp.dns_timeout = 10
        gp.hosts_ttl = 122
        # required for ifconfig and hipconf in Fedora
        # (rpm and "make install" targets)
        os.environ['PATH'] += ':/sbin:/usr/sbin:/usr/local/sbin'
        return

    def read_resolv_conf(gp, cfile=None):
        d = {}
        if not cfile:
            cfile = gp.resolv_conf
        f = file(cfile)
        for l in f.xreadlines():
            l = l.strip()
            if not d.has_key('nameserver'):
                r1 = gp.re_nameserver.match(l)
                if r1:
                    d['nameserver'] = r1.group(1)
        gp.resolvconfd = d
        if gp.server_ip == None:
            s_ip = gp.resolvconfd.get('nameserver')
            if s_ip:
                gp.server_ip = s_ip
            else:
                gp.server_ip = None
        return d

    def parameter_defaults(gp):
        env = os.environ
        if gp.server_ip == None:
            gp.server_ip = env.get('SERVER',None)
	if gp.server_port == None:
            server_port = env.get('SERVERPORT',None)
            if server_port != None:
                gp.server_port = int(server_port)
	if gp.server_port == None:
            gp.server_port = 53
	if gp.bind_ip == None:
            gp.bind_ip = env.get('IP',None)
	if gp.bind_ip == None:
            gp.bind_ip = '127.0.0.53'
	if gp.bind_port == None:
            bind_port = env.get('PORT',None)
            if bind_port != None:
                gp.bind_port = int(bind_port)
	if gp.bind_port == None:
            gp.bind_port = 53
	if gp.bind_alt_port == None:
            gp.bind_alt_port = 5000

    def hosts_recheck(gp):
        for h in gp.hosts:
            h.recheck()
        return

    def getname(gp,hn):
        for h in gp.hosts:
            r = h.getname(hn)
            if r:
                return r
        return None

    def getaddr(gp,ahn):
        for h in gp.hosts:
            r = h.getaddr(ahn)
            if r:
                return r
        return None

    def getaaaa(gp,ahn):
        for h in gp.hosts:
            r = h.getaaaa(ahn)
            if r:
                return r
        return None

    def cache_name(gp, name, addr):
        for h in gp.hosts:
            h.cache_name(name, addr)

    def geta(gp,ahn):
        for h in gp.hosts:
            r = h.geta(ahn)
            if r:
                return r
        return None

    def forkme(gp):
        pid = os.fork()
        if pid:
            return False
        else:
            # we are the child
            global myid
            myid = '%d-%d' % (time.time(),os.getpid())
            gp.logger = Logger()
            gp.fout = gp.logger
            gp.logger.setsyslog()
            return True

    # TBD: proper error handling
    def killold(gp):
        f = None
        try:
            f = file(gp.pidfile, 'r')
        except:
            pass # TBD: should ignore only "no such file or dir"
        if f:
            try:
                os.kill(int(f.readline().rstrip()), signal.SIGTERM)
            except OSError, (errno, strerror):
                pass # TBD: should ignore only "no such process"
            # sys.stdout.write('Ignoring kill error (%s) %s\n' % (errno, strerror))
            time.sleep(3)
            f.close()

    # TBD: error handling
    def savepid(gp):
        f = file(gp.pidfile, 'w')
        if f:
            f.write('%d\n' % (os.getpid(),))
            f.close()

    def dht_lookup(gp, nam):
    	#gp.fout.write("DHT look up\n")
        cmd = "hipconf dht get " + nam + " 2>&1"
        #gp.fout.write("Command: %s\n" % (cmd))
        p = os.popen(cmd, "r")
        result = p.readline()
        while result:
            start = result.find("2001:001")
            end = result.find("\n") -1
            if start != -1 and end != -1:
                return result[start:end]
            result = p.readline()
        return None

    def send_id_map_to_hipd(gp, nam):
    	cmd = "hipconf dnsproxy " + nam + " 2>&1"
     	#gp.fout.write("cmd - %s\n" % (cmd,))
	p = os.popen(cmd, "r")
	result = p.readline()
        #fout.write("Result: %s" % (result))
	if result.find("hipconf") != -1:
      	    # the result of "hipconf dnsproxy" gives us
            # an "hipconf add map" command which we can
            # directly invoke from command line
            #fout.write("Mapping to hipd\n")
	    result = result + " >/dev/null 2>&1"
	    #fout.write('Command: %s\n' % (result))
	    p = os.popen(result)
	#else:
            #fout.write("did not find\n")

    def hip_lookup(gp, q1, r, qtype, d2, connected):
        m = None
        lr = None
        nam = q1['qname']
        #gp.fout.write('Query type %d for %s\n' % (qtype, nam))
        lr_a =  gp.geta(nam)
        lr_aaaa = gp.getaaaa(nam)
        lr_ptr = gp.getaddr(nam)

        if qtype == 1:
            lr = lr_a
        elif qtype == 28 or qtype == 55 or qtype == 255:
            lr = lr_aaaa
        elif qtype == 12:
            lr = lr_ptr

        if lr:
            a2 = {'name': nam,
                  'data': lr,
                  'type': qtype,
                  'class': 1,
                  'ttl': gp.hosts_ttl,
                  }
            gp.fout.write('Hosts file or cache match: %s %s\n' %
                          (a2['name'],a2['data']))
            m = DNS.Lib.Mpacker()
            m.addHeader(r.header['id'],
                        1, 0, 0, 0, 1, 1, 0, 0,
                        1, 1, 0, 0)
            m.addQuestion(nam,qtype,1)

            if qtype == 1:
 	        m.addA(a2['name'],a2['class'],a2['ttl'],a2['data'])
            elif qtype == 28 or qtype == 55 or qtype == 255:
                m.addAAAA(a2['name'],a2['class'],a2['ttl'],a2['data'])
            elif qtype == 12:
                m.addPTR(a2['name'],a2['class'],a2['ttl'],a2['data'])
            gp.send_id_map_to_hipd(nam)
        elif connected and qtype != 1 and qtype != 12:
            dhthit = None
            #gp.fout.write('Query DNS for %s\n' % nam)
            r1 = d2.req(name=q1['qname'],qtype=255) # 55 is HIP RR
            #gp.fout.write('r1: %s\n' % (dir(r1),))

            dns_hit_found = False
            for a1 in r1.answers:
                if a1['typename'] == '55':
                    dns_hit_found = True
                    break
                
            if not dns_hit_found:
                dhthit = gp.dht_lookup(nam)
                if dhthit:
                    gp.fout.write('DHT match: %s %s\n' %
                                  (nam, dhthit))
                    dhtres = {'typename' : '55',
                              'name': nam,
                              'data': dhthit,
                              'type': qtype,
                              'class': 1,
                              'ttl': gp.hosts_ttl,
                           }
                    r1.answers.append(dhtres)

            hit_found = False
            for a1 in r1.answers:
                 if a1['typename'] == '55':
                     hit_found = True
                     if dhthit:
                         # dht query returns string
                         hit = dhthit
                     else:
                         # dns query returns binary, convert
                         # to string
                         aa1d = a1['data']
                         hit = pyip6.inet_ntop(aa1d[4:4+16])
                     a2 = {'name': a1['name'],
                           'data': hit,
                           'type': qtype,
                           'class': 1,
                           'ttl': a1['ttl'],
                           }
                     #gp.fout.write('%s\n' % (a2,))
                     m = DNS.Lib.Mpacker()
                     m.addHeader(r.header['id'],
                                 1, r1.header['opcode'], 0, 0,
                                 r1.header['rd'], 1, 0, 0,
                                 1, 1, 0, 0)
                     m.addQuestion(a1['name'],qtype,1)
		     m.addAAAA(a2['name'],a2['class'],a2['ttl'],a2['data'])

                     # To avoid forgetting IP address corresponding to HIT,
                     # store the mapping to hipd
                     for id in r1.answers:
                         ip = None
                         if id['type'] == 1:
                             ip = id['data']
                         elif id['type'] == 28:
                             aa1d = id['data']
                             ip = pyip6.inet_ntop(aa1d[0:0+16])
                         if ip != None:
                             cmd = "hipconf add map " + hit + " " + ip + \
                                   " >/dev/null 2>&1"
                             gp.fout.write('Associating DNS HIT %s with IP %s\n' %\
                                           (hit, ip))
                             os.system(cmd)

                     gp.send_id_map_to_hipd(nam)

                     gp.cache_name(a2['name'], a2['data'])
                     break

        return m


    def doit(gp,args):
        connected = False
        fout = gp.fout

        fout.write('Dns proxy for HIP started\n')

        gp.parameter_defaults()

	# Default virtual interface and address for dnsproxy to
	# avoid problems with other dns forwarders (e.g. dnsmasq)
	os.system("ifconfig lo:53 127.0.0.53")
	#os.system("ifconfig lo:53 inet6 add ::53/128")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((gp.bind_ip, gp.bind_port))
        except:
            fout.write('Port %d occupied, falling back to port %d\n' %
                       (gp.bind_port, gp.bind_alt_port))
            s.bind((gp.bind_ip, gp.bind_alt_port))
            gp.use_alt_port = True
            
        s.settimeout(gp.app_timeout)

        if (gp.use_alt_port):
            alt_port = gp.bind_alt_port
        else:
            alt_port = 0

        rc1 = ResolvConf(alt_port)

        if (rc1.get_dnsmasq_hook_status() and rc1.is_resolvconf_in_use()):
            fout.write('Dnsmasq-resolvconf installation detected\n')
            conf_file = rc1.guess_resolvconf()
        else:
            conf_file = None
            
        if (conf_file != None):
            fout.write("Using conf file %s\n" % conf_file)
        gp.read_resolv_conf(conf_file)
        if (gp.server_ip != None):
            fout.write("DNS server is %s\n" % gp.server_ip)

        gp.hosts = []
        if gp.hostsnames:
            for hn in gp.hostsnames:
                gp.hosts.append(hosts.Hosts(hn))
        else:
            if os.path.exists(gp.default_hiphosts):
                gp.hosts.append(hosts.Hosts(gp.default_hiphosts))

        if os.path.exists(gp.default_hosts):
            gp.hosts.append(hosts.Hosts(gp.default_hosts))

        util.init_wantdown()
        util.init_wantdown_int()        # Keyboard interrupts

        args0 = {'server': gp.bind_ip,
                }
        rc1.start()
        rc1.write({'nameserver': gp.bind_ip})

        if not (rc1.is_resolvconf_in_use() and rc1.get_dnsmasq_hook_status()):
            fout.write('Rewrote resolv.conf\n')
        if rc1.get_dnsmasq_hook_status():
            fout.write('Hooked with dnsmasq\n')

        if (gp.server_ip != None):
            if gp.server_ip.find(':') == -1:
                server_family = socket.AF_INET
            else:
                server_family = socket.AF_INET6
            s2 = socket.socket(server_family, socket.SOCK_DGRAM)
            s2.settimeout(gp.dns_timeout)
            try:
                s2.connect((gp.server_ip,gp.server_port))
                connected = True
            except:
                connected = False

        while not util.wantdown():
            try:
                gp.hosts_recheck()
                if rc1.old_has_changed():
                    connected = False
                    gp.server_ip = rc1.resolvconfd.get('nameserver')
                    if gp.server_ip != None:
                        if gp.server_ip.find(':') == -1:
                            server_family = socket.AF_INET
                        else:
                            server_family = socket.AF_INET6
                        s2 = socket.socket(server_family, socket.SOCK_DGRAM)
                        s2.settimeout(gp.dns_timeout)
                    if (gp.server_ip != None):
                        try:
                            s2.connect((gp.server_ip,gp.server_port))
                            connected = True
                            fout.write("DNS server is %s\n" % gp.server_ip)
                        except:
                            connected = False

                    rc1.restart()
                    rc1.write({'nameserver': gp.bind_ip})
                    if not (rc1.is_resolvconf_in_use() and
                            rc1.get_dnsmasq_hook_status()):
                        fout.write('Rewrote resolv.conf\n')
                try:
                    buf,from_a = s.recvfrom(2048)
                except socket.timeout:
                    continue;

                #fout.write('Up %s\n' % (util.tstamp(),))
                #fout.write('%s %s\n' % (from_a,repr(buf)))
                fout.flush()
                u = DNS.Lib.Munpacker(buf)
                r = DNS.Lib.DnsResult(u,args0)
                #fout.write('%s %s\n' % (r.header,r.questions,))
                q1 = r.questions[0]
                qtype = q1['qtype']
                sent_answer = 0
                m = None

		# IPv4 A record
		# IPv6 AAAA record
                # ANY address
		if qtype == 1 or qtype == 28 or qtype == 255 or qtype == 12 or qtype == 55:
                    d2 = DNS.DnsRequest(server=gp.server_ip,
                                        port=gp.server_port,
                                        timeout=gp.dns_timeout)
		    m = gp.hip_lookup(q1, r, qtype, d2, connected)
		    if m:
			try:
			    #fout.write("sending %d answer\n" % qtype)
                            s.sendto(m.buf,from_a)
                            sent_answer = 1
		        except Exception,e:
		            fout.write('Exception: %s\n' % e)

                else:
                    fout.write('Unhandled type %d\n' % qtype)

		if connected and not sent_answer:
		    #fout.write('No HIP-related records found\n')
                    s2.send(buf)
                    r2 = s2.recv(2048)
                    u = DNS.Lib.Munpacker(r2)
                    r = DNS.Lib.DnsResult(u,args0)
                    #fout.write('Bypass %s %s %s\n' % (r.header,r.questions,r.answers,))
                    if r.header.get('status') != 'NXDOMAIN':
                        s.sendto(r2,from_a)

                fout.flush()

            except Exception,e:
                fout.write('Exception: %s\n' % (e,))

        if rc1.get_dnsmasq_hook_status():
            fout.write('Removing dnsmasq hooks\n')
        fout.write('Wants down\n')
        fout.flush()
        rc1.stop()
        if not (rc1.is_resolvconf_in_use() and rc1.get_dnsmasq_hook_status()):
            fout.write('resolv.conf restored\n')
        fout.flush()
        return

def main(argv):
    gp = Global()
    try:
        opts, args = getopt.getopt(argv[1:],
                                   'bkhf:c:H:s:p:l:i:P:',
                                   ['background',
                                    'kill',
                                    'help',
                                    'file=',
                                    'count=',
                                    'hosts=',
                                    'server=',
                                    'serverport=',
                                    'ip=',
                                    'port=',
                                    'pidfile='
                                    ])
    except getopt.error, msg:
        usage(1, msg)

    for opt, arg in opts:
        if opt in ('-k', '--kill'):
            gp.kill = True
        elif opt in ('-b', '--background'):
            gp.fork = True
        elif opt in ('-h', '--help'):
            usage(0)
        elif opt in ('-f', '--file'):
            gp.tarfilename = arg
        elif opt in ('-c', '--count'):
            gp.fetchcount = int(arg)
        elif opt in ('-H', '--hosts'):
            gp.hostsnames.append(arg)
        elif opt in ('--resolv-conf',):
            gp.resolv_conf = arg
        elif opt in ('-s', '--server'):
            gp.server_ip = arg
        elif opt in ('-p', '--serverport'):
            gp.server_port = int(arg)
        elif opt in ('-i', '--ip'):
            gp.bind_ip = arg
        elif opt in ('-l', '--port'):
            gp.bind_port = int(arg)
        elif opt in ('-P', '--pidfile'):
            gp.pidfile = arg

    child = False;
    if (gp.fork):
        child = gp.forkme()

    if (child or gp.fork == False):
        if (gp.kill):
            gp.killold()
        gp.savepid()
        gp.doit(args)
        
if __name__ == '__main__':
    main(sys.argv)
