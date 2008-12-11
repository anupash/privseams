#! /usr/bin/env python

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
    re_nameserver = re.compile(r'nameserver\s([0-9\.]+)$')
    def guess_resolvconf(self):
        if (os.path.isdir('/etc/resolvconf/.') and
            os.path.exists('/sbin/resolvconf') and
            os.path.exists('/etc/resolvconf/run/resolv.conf')):
            # We have probably resoconf package installed
           return '/etc/resolvconf/run/resolv.conf'
        else:
           return '/etc/resolv.conf'
    def __init__(self,filetowatch = None):
        self.oktowrite = 0
        self.resolvconf_towrite = None
        if filetowatch == None:
            filetowatch = self.guess_resolvconf()
        self.resolvconf_orig = filetowatch
        self.filetowatch = filetowatch
        self.old_rc_mtime = os.stat(self.filetowatch).st_mtime
        self.resolvconf_towrite = '/etc/resolv.conf'
        return
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
        if old_rc_mtime > self.old_rc_mtime:
            self.reread_old_rc()
            self.old_rc_mtime = old_rc_mtime
            return 1
        else:
            return 0
    def save_resolvconf(self):
        #st1 = os.lstat(self.resolvconf_towrite)
        self.resolvconf_bkname = '%s-%s' % (self.resolvconf_towrite,myid)
        os.link(self.resolvconf_towrite,self.resolvconf_bkname)
        return
    def restore_resolvconf(self):
        os.remove(self.resolvconf_towrite)
        os.rename(self.resolvconf_bkname,self.resolvconf_towrite)
        return
    def write(self,params):
        if not self.oktowrite:
            throw(ResolvConfError('Cannot write resolv.conf'))

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

    def start(self):
        self.save_resolvconf()
        if self.resolvconf_towrite:
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
            self.oktowrite = 1

    def restart(self):
        if os.path.exists(self.resolvconf_bkname):
            os.remove(self.resolvconf_bkname)
        self.start()
        self.old_rc_mtime = os.stat(self.filetowatch).st_mtime

    def stop(self):
        self.oktowrite = 0
        self.restore_resolvconf()
	os.system("ifconfig lo:53 down")

class Global:
    default_hiphosts = "/etc/hip/hosts"
    re_nameserver = re.compile(r'nameserver\s([0-9\.]+)$')
    def __init__(gp):
        gp.resolv_conf = '/etc/resolv.conf'
        gp.hostsnames = []
	gp.server_ip = None
	gp.server_port = None
	gp.bind_ip = None
	gp.bind_port = None
        gp.fork = False
        gp.pidfile = '/var/run/dnshipproxy.pid'
        gp.kill = False
        gp.fout = sys.stdout
        gp.app_timeout = 1
        gp.dns_timeout = 10
        gp.hosts_ttl = 122
        # required for ifconfig and hipconf in Fedora
        # (rpm and "make install" targets)
        os.environ['PATH'] += ':/sbin:/usr/sbin:/usr/local/sbin'
        return

    def read_resolv_conf(gp):
        d = {}
        f = file(gp.resolv_conf)
        for l in f.xreadlines():
            l = l.strip()
            if not d.has_key('nameserver'):
                r1 = gp.re_nameserver.match(l)
                if r1:
                    d['nameserver'] = r1.group(1)
        gp.resolvconfd = d
        return d

    def parameter_defaults(gp):
        env = os.environ
        gp.server_ip_from_old_rc = 0
        if gp.server_ip == None:
            gp.server_ip = env.get('SERVER',None)
        if gp.server_ip == None:
            s_ip = gp.resolvconfd.get('nameserver')
            if s_ip:
                gp.server_ip = s_ip
                gp.server_ip_from_old_rc = 1
            else:
                gp.server_ip = '127.0.0.53' # xx fixme
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

    def bamboo_lookup(gp, nam, addrtype):
    	gp.fout.write("DHT look up\n")
        gp.fout.write("Command: - %s\n" % (cmd))
        cmd = "hipconf dht get " + nam + " 2>&1"
        p = os.popen(cmd, "r")
        result = p.readline()
        while result:
            if result.find("Result") != -1:
            	gp.fout.write("Found id: %s\n" % (result));
            else:
                gp.fout.write("Skip: %s\n" % (result))
            result = p.readline()

    def send_id_map_to_hipd(gp, nam):
    	cmd = "hipconf dnsproxy " + nam + " 2>&1"
     	#fout.write("cmd - %s %s\n" % (cmd,nam))
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

    def dns_any_lookup(gp, q1, r, qtype, d2):
        m = gp.dns_aaaa_lookup(q1, r, qtype, d2)
        if m == None:
	    m = gp.dns_a_lookup(q1, r, qtype)
        return m

    def dns_a_lookup(gp, q1, r, qtype):
        gp.fout.write('Query type A: LSI look up\n')
	nam = q1['qname']
	lr = gp.geta(nam)
        m = None        
        if lr:
            a2 = {'name': nam,
                  'data': lr,
                  'type': 28,
                  'class': 1,
                  'ttl': 10,
                 }
            gp.fout.write('Hosts file A  %s\n' % (a2,))
            m = DNS.Lib.Mpacker()
            m.addHeader(r.header['id'],
                        0, 0, 0, 0, 1, 0, 0, 0,
                        1, 1, 0, 0)
            m.addQuestion(nam,qtype,1)
 	    m.addA(a2['name'],a2['class'],a2['ttl'],a2['data'])
        return m

    def hip_lookup(gp, q1, r, qtype, d2):
        m = None
        lr = None
        nam = q1['qname']
        gp.fout.write('Query type %d for %s\n' % (qtype, nam))
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
            gp.fout.write('Hosts file match %s\n' % (a2,))
            m = DNS.Lib.Mpacker()
            m.addHeader(r.header['id'],
                        0, 0, 0, 0, 1, 0, 0, 0,
                        1, 1, 0, 0)
            m.addQuestion(nam,qtype,1)

            if qtype == 1:
 	        m.addA(a2['name'],a2['class'],a2['ttl'],a2['data'])
            elif qtype == 28 or qtype == 55 or qtype == 255:
                m.addAAAA(a2['name'],a2['class'],a2['ttl'],a2['data'])
            elif qtype == 12:
                m.addPTR(a2['name'],a2['class'],a2['ttl'],a2['data'])
        elif qtype != 1 and qtype != 12:
            r1 = d2.req(name=q1['qname'],qtype=55) # 55 is HIP RR
            gp.fout.write('Query DNS for %s\n' % nam)
            gp.fout.write('r1: %s\n' % (dir(r1),))
            gp.fout.write('r1.answers: %s\n' % (r1.answers,))
            for a1 in r1.answers:
                 if a1['typename'] == '55':
                     aa1d = a1['data']
                     aa1 = aa1d[4:4+16]
                     a2 = {'name': a1['name'],
                           'data': pyip6.inet_ntop(aa1),
                           'type': qtype,
                           'class': 1,
                           'ttl': a1['ttl'],
                           }
                     gp.fout.write('%s\n' % (a2,))
                     m = DNS.Lib.Mpacker()
                     m.addHeader(r.header['id'],
                                 0, r1.header['opcode'], 0, 0,
                                 r1.header['rd'], 0, 0, 0,
                                 1, 1, 0, 0)
                     m.addQuestion(a1['name'],qtype,1)
		     m.addAAAA(a2['name'],a2['class'],a2['ttl'],a2['data'])
                     gp.send_id_map_to_hipd(nam)
                     gp.cache_name(a2['name'], a2['data'])
                     break

        return m


    def doit(gp,args):
        gp.read_resolv_conf()
        gp.parameter_defaults()
        gp.hosts = []
        if gp.hostsnames:
            for hn in gp.hostsnames:
                gp.hosts.append(hosts.Hosts(hn))
        else:
            if os.path.exists(gp.default_hiphosts):
                gp.hosts.append(hosts.Hosts(gp.default_hiphosts))
        util.init_wantdown()
        util.init_wantdown_int()        # Keyboard interrupts
        fout = gp.fout

	# Default virtual interface and address for dnsproxy to
	# avoid problems with other dns forwarders (dnsmasq)
	os.system("ifconfig lo:53 127.0.0.53")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((gp.bind_ip,gp.bind_port))
        s.settimeout(gp.app_timeout)

        args0 = {'server': '127.0.0.53',
                }

        d2 = DNS.DnsRequest(server=gp.server_ip,port=gp.server_port,timeout=0.2)

        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.settimeout(gp.dns_timeout)
        s2.connect((gp.server_ip,gp.server_port))

        rc1 = ResolvConf()
        rc1.start()
        fout.write('Rewriting resolv.conf\n')
        rc1.write({'nameserver': gp.bind_ip})

        fout.write('Dns proxy for HIP started\n')
        while not util.wantdown():
            try:
                gp.hosts_recheck()
                if gp.server_ip_from_old_rc:
                    if rc1.old_has_changed():
                        s2.close()
                        gp.server_ip = rc1.resolvconfd.get('nameserver')
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s2.settimeout(gp.dns_timeout)
                        s2.connect((gp.server_ip,gp.server_port))
                        fout.write('Rewriting resolv.conf\n')
                        rc1.restart()
                try:
                    buf,from_a = s.recvfrom(2048)
                except socket.timeout:
                    continue;

                fout.write('Up %s\n' % (util.tstamp(),))
                fout.write('%s %s\n' % (from_a,repr(buf)))
                fout.flush()
                u = DNS.Lib.Munpacker(buf)
                r = DNS.Lib.DnsResult(u,args0)
                fout.write('%s %s\n' % (r.header,r.questions,))
                q1 = r.questions[0]
                qtype = q1['qtype']
                sent_answer = 0
                m = None

		# IPv4 A record
		# IPv6 AAAA record
                # ANY address
		if qtype == 1 or qtype == 28 or qtype == 255 or qtype == 12:
		    m = gp.hip_lookup(q1, r, qtype, d2)
		    if m:
			try:
			    fout.write("sending %d answer\n" % qtype)
                            s.sendto(m.buf,from_a)
                            sent_answer = 1
		        except Exception,e:
		            fout.write('Exception: %s\n' % e)

                else:
                    fout.write('Unhandled type %d\n' % qtype)

		if not sent_answer:
		    fout.write('No HIP-related records found\n')
                    s2.send(buf)
                    r2 = s2.recv(2048)
                    u = DNS.Lib.Munpacker(r2)
                    r = DNS.Lib.DnsResult(u,args0)
                    fout.write('Bypass %s %s %s\n' % (r.header,r.questions,r.answers,))
                    if r.header.get('status') != 'NXDOMAIN':
                        s.sendto(r2,from_a)

                fout.flush()

            except Exception,e:
                fout.write('Exception ignored: %s\n' % (e,))

        fout.write('Wants down\n')
        fout.flush()
        rc1.stop()
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
