#! /usr/bin/env python

import sys
import getopt
import os
import time
import util
import socket
import DNS
import DNS.pyip6
import binascii
import hosts

def usage(utyp, *msg):
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

class Global:
    def __init__(gp):
        gp.resolv_conf = '/etc/resolv.conf'
        gp.hostsnames = []
        return
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
        gp.hosts = []
        for hn in gp.hostsnames:
            gp.hosts.append(hosts.Hosts(hn))
        util.init_wantdown()
        fout = sys.stdout
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        IP = os.environ['IP']
        PORT = int(os.environ['PORT'])
        s.bind((IP,PORT))

        server = os.environ['SERVER']
        serverport = int(os.environ['SERVERPORT'])

        args0 = {'server': '127.0.0.1',
                }

        d2 = DNS.DnsRequest(server=server,port=serverport,timeout=0.2)

        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.connect((server,serverport))

        while not util.wantdown():
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
                    fout.write('%s\n' % (r1.answers,))
                    a1 = r1.answers[0]
                    aa1d = a1['data']
                    aa1 = aa1d[4:4+16]
                    a2 = {'name': a1['name'],
                          'data': DNS.pyip6.inet_ntop(aa1),
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
                m.addAAAA(a2['name'],a2['class'],a2['ttl'],a2['data'])
                s.sendto(m.buf,from_a)
            else:
                s2.send(buf)
                r2 = s2.recv(2048)

                u = DNS.Lib.Munpacker(r2)
                r = DNS.Lib.DnsResult(u,args0)
                fout.write('Bypass %s %s %s\n' % (r.header,r.questions,r.answers,))

                if r.header.get('status') != 'NXDOMAIN':
                    s.sendto(r2,from_a)

            fout.flush()

        fout.write('Wants down\n')
        fout.flush()
        return

def main(argv):
    gp = Global()
    try:
        opts, args = getopt.getopt(argv[1:],
                                   'hf:c:H:',
                                   ['help',
                                    'file=',
                                    'count=',
                                    'hosts=',
                                    'resolv-conf=',
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

    gp.doit(args)
        
if __name__ == '__main__':
    main(sys.argv)
