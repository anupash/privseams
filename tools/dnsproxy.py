#! /usr/bin/env python

import sys
import getopt
import os
import time
import util
import socket
import DNS
import pyip6
import binascii
import hosts
import re

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

def has_resolvconf0():
    path2 = list(path)
    if not '/sbin' in path2:
        path2.append('/sbin')
    for d in path2:
        if os.path.exists(os.path.join(d,'resolvconf')):
            return True
    return False

has_resolvconf = has_resolvconf0()

class Global:
    re_nameserver = re.compile(r'nameserver\s([0-9\.]+)$')
    def __init__(gp):
        gp.resolv_conf = '/etc/resolv.conf'
        gp.hostsnames = []
	gp.server_ip = None
	gp.server_port = None
	gp.bind_ip = None
	gp.bind_port = None
        return

    def read_resolv_conf(gp):
        d = {}
        gp.resolvconfd = d
        f = file(gp.resolv_conf)
        for l in f.xreadlines():
            l = l.strip()
            if not d.has_key('nameserver'):
                r1 = gp.re_nameserver.match(l)
                if r1:
                    d['nameserver'] = r1.group(1)
        return d

    def parameter_defaults(gp):
        env = os.environ
        if gp.server_ip == None:
            gp.server_ip = env.get('SERVER',None)
        if gp.server_ip == None:
            s_ip = gp.resolvconfd.get('nameserver')
            if s_ip:
                gp.server_ip = s_ip
            else:
                gp.server_ip = '127.0.0.1' # xx fixme
	if gp.server_port == None:
            server_port = env.get('SERVERPORT',None)
            if server_port != None:
                gp.server_port = int(server_port)
	if gp.server_port == None:
            gp.server_port = 53
	if gp.bind_ip == None:
            gp.bind_ip = env.get('IP',None)
	if gp.bind_ip == None:
            gp.bind_ip = '127.0.0.1'
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

    def getbyname(gp,hn):
        for h in gp.hosts:
            r = h.getbyname(hn)
            if r:
                return r
        return None

    def doit(gp,args):
        gp.read_resolv_conf()
        gp.parameter_defaults()
        gp.hosts = []
        for hn in gp.hostsnames:
            gp.hosts.append(hosts.Hosts(hn))
        util.init_wantdown()
        fout = sys.stdout
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((gp.bind_ip,gp.bind_port))


        args0 = {'server': '127.0.0.1',
                }

        d2 = DNS.DnsRequest(server=gp.server_ip,port=gp.server_port,timeout=0.2)

        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.connect((gp.server_ip,gp.server_port))

        while not util.wantdown():
            try:
                gp.hosts_recheck()
                buf,from_a = s.recvfrom(2048)
                fout.write('Up %s\n' % (util.tstamp(),))
                fout.write('%s %s\n' % (from_a,repr(buf)))
                fout.flush()
                u = DNS.Lib.Munpacker(buf)
                r = DNS.Lib.DnsResult(u,args0)
                fout.write('%s %s\n' % (r.header,r.questions,))
                q1 = r.questions[0]
                qtype = q1['qtype']
                sent_anser = 0
                m = None
                if qtype == 28:     # AAAA
                    nam = q1['qname']
                    lr = gp.getbyname(nam)
                    if lr:
                        a2 = {'name': nam,
                              'data': lr,
                              'type': 28,
                              'class': 1,
                              'ttl': 10,
                              }
                        fout.write('Hosts A2  %s\n' % (a2,))
                        m = DNS.Lib.Mpacker()
                        m.addHeader(r.header['id'],
                                    0, 0, 0, 0, 1, 0, 0, 0,
                                    1, 1, 0, 0)
                        m.addQuestion(nam,qtype,1)
                    else:
                        r1 = d2.req(name=q1['qname'],qtype=55) # 55 is HIP RR
                        fout.write('r1: %s\n' % (dir(r1),))
                        fout.write('r1.answers: %s\n' % (r1.answers,))
                        if r1.answers:
                            a1 = r1.answers[0]
                            aa1d = a1['data']
                            aa1 = aa1d[4:4+16]
                            a2 = {'name': a1['name'],
                                  'data': pyip6.inet_ntop(aa1),
                                  'type': 28,
                                  'class': 1,
                                  'ttl': a1['ttl'],
                                  }
                            fout.write('DNS A2  %s\n' % (a2,))
                            m = DNS.Lib.Mpacker()
                            m.addHeader(r.header['id'],
                                        0, r1.header['opcode'], 0, 0, r1.header['rd'], 0, 0, 0,
                                        1, 1, 0, 0)
                            m.addQuestion(a1['name'],qtype,1)
                        else:
                            m = None
                    if m:
                        m.addAAAA(a2['name'],a2['class'],a2['ttl'],a2['data'])
                        s.sendto(m.buf,from_a)
                        sent_anser = 1

                if not sent_anser:
                    s2.send(buf)
                    r2 = s2.recv(2048)

                    u = DNS.Lib.Munpacker(r2)
                    r = DNS.Lib.DnsResult(u,args0)
                    fout.write('Bypass %s %s %s\n' % (r.header,r.questions,r.answers,))

                    if r.header.get('status') != 'NXDOMAIN':
                        s.sendto(r2,from_a)

                fout.flush()
            except Exception,e:
                fout.write('Exception %s\n' % (e,))
                
        fout.write('Wants down\n')
        fout.flush()
        return

def main(argv):
    gp = Global()
    try:
        opts, args = getopt.getopt(argv[1:],
                                   'hf:c:H:s:p:l:i:',
                                   ['help',
                                    'file=',
                                    'count=',
                                    'hosts=',
                                    'server=',
                                    'serverport=',
                                    'ip=',
                                    'port=',
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

    gp.doit(args)
        
if __name__ == '__main__':
    main(sys.argv)
