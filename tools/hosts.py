#! /usr/bin/env python

import sys
import getopt
import os
import pyip6
import binascii

def usage(utyp, *msg):
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

class Hosts:
    def __init__(self,filename,resolv_conf=None):
        self.hostsfile = filename
        self.modified = None
        self.rcmodified = None
        if not resolv_conf:
            resolv_conf = '/etc/resolv.conf'
        self.resolv_conf = resolv_conf
        self.d = {}
        self.a = {}
        self.aaaa = {}
        self.recheck()
        return

    def recheck(self):
        st0 = os.stat(self.resolv_conf)
        if (self.rcmodified == None or
            st0.st_mtime > self.rcmodified):
            self.rcreread()
            self.rcmodified = st0.st_mtime
            self.modified = None
        st1 = os.stat(self.hostsfile)
        if (self.modified == None or
            st1.st_mtime > self.modified):
            self.reread()
            self.modified = st1.st_mtime
        return

    def sani(self,n):
        n = n.lower()
        a = n.split('.')
        while a and a[-1] == '':
            a.pop()
        return '.'.join(a)

    def sani_aaaa(self,a):
        a = pyip6.inet_pton(a)
        a2 = list(binascii.b2a_hex(a))
        a2.reverse()
        a2.extend(['ip6','arpa'])
        return '.'.join(a2)

    def rcreread(self):
        self.suffixes = ()
        f = file(self.resolv_conf)
        d = {}
        while 1:
            l = f.readline()
            if not l:
                break
            l = l.strip()
            if not l or l.startswith('#'):
                continue
            aa = l.split()
            kw = aa.pop(0)

            if kw == 'search':
                self.suffixes = tuple([i.lower() for i in aa])
        return

    def str_is_ipv6(self, addr_str):
        if addr_str.find(':') == -1:
            return False
        else:
            return True

    def str_is_hit(self, addr_str):
        if addr_str[0:8] == "2001:001" or addr_str[0:6] == "2001:1":
            return True
        else:
            return False

    def str_is_lsi(self, addr_str):
        if addr_str[0:2] == "1.":
            return True
        else:
            return False

    def reread(self):
        f = file(self.hostsfile)
        d = {}
        aaaa = {}
	a = {}
        while 1:
            l = f.readline()
            if not l:
                break
            l = l.strip()
            if not l or l.startswith('#'):
                continue
            aa = l.split()
            addr = aa.pop(0)
            for n in aa:
                n = self.sani(n)
                a2 = n.split('.')
                if len(a2) <= 1:
                    for s in self.suffixes:
                        d['%s.%s' % (n,s)] = addr
                d[n] = addr
                if self.str_is_ipv6(addr):
                    aaaa[n] = addr
                else:
                    a[n] = addr
        self.d = d
	self.a = a
        self.aaaa = aaaa
        return

    def getaddr(self,addr):
        for name in self.d:
            if self.sani(addr) == self.d[name]:
                return name
        return None

    def getname(self,n):
        return self.d.get(self.sani(n))

    def geta(self,n):
        return self.a.get(self.sani(n))

    def getaaaa(self,n):
        return self.aaaa.get(self.sani(n))

    # Overload hosts file as cache for hostname->HIT/LSI
    def cache_name(self, hostname, addr):
        self.d[hostname] = addr
        if self.str_is_hit(addr):
            self.aaaa[hostname] = addr
        elif self.str_is_lsi(addr):
            self.a[hostname] = addr

class Global:
    def __init__(gp):
        return
    def doit(gp,args):
        return

def main(argv):
    gp = Global()
    try:
        opts, args = getopt.getopt(argv[1:],
                                   'hf:c:',
                                   ['help',
                                    'file=',
                                    'count=',
                                    ])
    except getopt.error, msg:
        usage(1, msg)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(0)
        elif opt in ('-f', '--file'):
            gp.tarfilename = arg
        elif opt in ('-c', '--count'):
            gp.fetchcount = int(arg)

    gp.doit(args)
        
if __name__ == '__main__':
    main(sys.argv)
