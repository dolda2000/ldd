#    ldd - DNS implementation in Python
#    Copyright (C) 2006 Fredrik Tolf <fredrik@dolda2000.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import socket
import select
import time
import random

import proto
import rec
import dn

class error(Exception):
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text

class servfail(error):
    def __init__(self):
        error.__init__(self, "SERVFAIL")

class unreachable(error):
    def __init__(self, server):
        error.__init__(self, "could not reach server: " + str(server))

def resolvecnames(pkt, res = None):
    if res is None: res = default
    for q in pkt.qlist:
        cnrr = pkt.getanswer(q.name, rec.rtypebyname("CNAME"))
        if cnrr is not None:
            if pkt.getanswer(cnrr.data["priname"], q.rtype) is None:
                try:
                    resp = res.squery(cnrr.data["priname"], q.rtype)
                except error:
                    continue
                if resp is None:
                    continue
                anrr = resp.getanswer(cnrr.data["priname"], q.rtype)
                if anrr is None:
                    continue
                pkt.addan(anrr)

def resolveadditional(pkt, rr, res = None):
    if res is None: res = default
    for name in rr.data:
        if isinstance(rr.data[name], dn.domainname):
            for rtype in ["A", "AAAA"]:
                if pkt.getanswer(rr.data[name], rtype) is not None:
                    continue
                try:
                    resp = res.squery(rr.data[name], rtype)
                except error:
                    continue
                if resp is None:
                    continue
                anrr = resp.getanswer(rr.data[name], rtype)
                if anrr is None:
                    continue
                pkt.addad(anrr)

def extractaddrinfo(packet, name):
    ret = []
    for rr in packet.anlist + packet.adlist:
        if rr.head.name == name:
            if rr.head.istype("A"):
                ret += [(socket.AF_INET, socket.inet_ntop(socket.AF_INET, rr.data["address"]))]
            elif rr.head.istype("AAAA"):
                ret += [(socket.AF_INET6, socket.inet_ntop(socket.AF_INET6, rr.data["address"]))]
    return ret

def resolve(packet, nameserver, recurse, retries = 3, timeout = 2000, hops = 0, cnameres = None, verbose = False, visited = None):
    if cnameres is None: cnameres = default
    if visited is None: visited = set()
    visited |= set([nameserver])
    sk = socket.socket(nameserver[0], socket.SOCK_DGRAM)
    sk.bind(("", 0))
    for i in range(retries):
        sk.sendto(packet.encode(), nameserver[1:])
        p = select.poll()
        p.register(sk.fileno(), select.POLLIN)
        fds = p.poll(timeout)
        if (sk.fileno(), select.POLLIN) in fds:
            break
    else:
        raise unreachable(nameserver)
    ret = sk.recv(65536)
    sk.close()
    try:
        resp = proto.decodepacket(ret)
    except proto.malformedpacket, inst:
        raise error(str(inst))
    if resp.qid != packet.qid:
        raise error("got response with wrong qid(?!)")
    if "resp" not in resp.flags:
        raise error("got query in response")
    if resp.rescode != 0:
        if resp.rescode == proto.SERVFAIL:
            raise servfail()
        if resp.rescode == proto.NXDOMAIN:
            return resp
        raise error("non-successful response (" + str(resp.rescode) + ")")
    if recurse:
        resolvecnames(resp, cnameres)
    if not recurse or resp.hasanswers():
        return resp
    if not resp.hasanswers() and "auth" in resp.flags:
        return resp
    if hops > 30:
        raise error("too many levels deep")
    for rr in resp.aulist:
        if verbose:
            print (hops * " ") + "Checking " + str(rr)
        if rr.head.istype("NS"):
            if verbose:
                print (hops * " ") + "Will try " + str(rr)
            ai = extractaddrinfo(resp, rr.data["nsname"])
            if len(ai) == 0:
                if verbose:
                    print (hops * " ") + "Resolving nameservers for " + str(rr.data["nsname"])
                resolveadditional(resp, rr)
                ai = extractaddrinfo(resp, rr.data["nsname"])
            for ns in ai:
                ns += (53,)
                if ns in visited:
                    if verbose:
                        print (hops * " ") + "Will not try " + str(ns) + " again"
                    continue
                if verbose:
                    print (hops * " ") + "Trying " + str(ns)
                try:
                    resp2 = resolve(packet, ns, recurse, retries, timeout, hops + 1, verbose = verbose, visited = visited)
                except unreachable:
                    if verbose:
                        print (hops * " ") + "Could not reach " + str(ns)
                    continue
                if verbose:
                    if resp2 is None:
                        print (hops * " ") + "Got None"
                    else:
                        if "auth" in resp2.flags:
                            austr = "Auth"
                        else:
                            austr = "Nonauth"
                        print (hops * " ") + "Got " + str(resp2.hasanswers()) + " (" + austr + ")"
                if resp2 is not None and resp2.hasanswers():
                    return resp2
                if resp2 is not None and not resp2.hasanswers() and "auth" in resp2.flags:
                    return resp2
    return None

class resolver:
    def __init__(self, nameserver, recurse, nsrecurse = True, retries = 3, timeout = 2000, verbose = False):
        self.nameserver = nameserver
        self.recurse = recurse
        self.nsrecurse = nsrecurse
        self.retries = retries
        self.timeout = timeout
        self.verbose = verbose

    def resolve(self, packet):
        return resolve(packet, self.nameserver, self.recurse, self.retries, self.timeout, verbose = self.verbose)

    def squery(self, name, rtype):
        packet = proto.packet()
        try:
            if self.nsrecurse: packet.setflags(["recurse"])
        except AttributeError: pass
        packet.addq(rec.rrhead(name, rtype))
        return self.resolve(packet)

class multiresolver(resolver):
    def __init__(self, resolvers):
        self.rl = [{"res": res, "qs": []} for res in resolvers]
        self.lastclean = int(time.time())

    def clean(self):
        now = int(time.time())
        if now - self.lastclean < 60:
            return
        self.lastclean = now
        for r in self.rl:
            nl = []
            for q in r["qs"]:
                if now - q["time"] < 1800:
                    nl += [q]
            r["qs"] = nl
        
    def resolve(self, packet):
        self.clean()
        l = []
        ts = 0
        for r in self.rl:
            if len(r["qs"]) < 1:
                score = 1.0
            else:
                score = float(sum([q["s"] for q in r["qs"]])) / len(r["qs"])
            l += [(score, r)]
            ts += score
        c = random.random() * ts
        for score, r in l:
            c -= score
            if c <= 0:
                break
        else:
            assert(False)
        try:
            res = r["res"].resolve(packet)
        except error:
            r["qs"] = r["qs"][:10] + [{"time": int(time.time()), "s": 0}]
            raise
        r["qs"] = r["qs"][:10] + [{"time": int(time.time()), "s": 1}]
        return res

class sysresolver(resolver):
    def __init__(self, conffile = "/etc/resolv.conf"):
        nslist = []
        prelist = []
        a = open(conffile, "r")
        for line in (l.strip() for l in a):
            p = line.find(" ")
            if p >= 0:
                c = line[:p]
                line = line[p + 1:]
                if c == "nameserver":
                    try:
                        socket.inet_pton(socket.AF_INET, line)
                    except socket.error: pass
                    else:
                        nslist += [(socket.AF_INET, line, 53)]
                    try:
                        socket.inet_pton(socket.AF_INET6, line)
                    except socket.error: pass
                    else:
                        nslist += [(socket.AF_INET6, line, 53)]
                if c == "domain" or c == "search":     # How do these differ?
                    prelist += line.split()
        a.close()
        rl = []
        for ns in nslist:
            rl += [resolver(ns, False, True)]
        self.resolver = multiresolver(rl)
        self.prelist = []
        for prefix in prelist:
            pp = dn.fromstring(prefix)
            pp.rooted = True
            self.prelist += [pp]

    def resolve(self, packet):
        res = self.resolver.resolve(packet)
        return res

    def squery(self, name, rtype):
        if type(name) == str:
            name = dn.fromstring(name)
        if not name.rooted:
            namelist = [name + prefix for prefix in self.prelist] + [name + dn.fromstring(".")]
        else:
            namelist = [name]
        for name in namelist:
            packet = proto.packet()
            packet.setflags(["recurse"])
            packet.addq(rec.rrhead(name, rtype))
            res = self.resolve(packet)
            if res.rescode == 0:
                break
        return res

sysres = sysresolver()
rootresolvers = {"a": resolver((socket.AF_INET, "198.41.0.4", 53), True, False),
                 "b": resolver((socket.AF_INET, "192.228.79.201", 53), True, False),
                 "c": resolver((socket.AF_INET, "192.33.4.12", 53), True, False),
                 "d": resolver((socket.AF_INET, "128.8.10.90", 53), True, False),
                 "e": resolver((socket.AF_INET, "192.203.230.10", 53), True, False),
                 "f": resolver((socket.AF_INET, "192.5.5.241", 53), True, False),
                 "g": resolver((socket.AF_INET, "192.112.36.4", 53), True, False),
                 "h": resolver((socket.AF_INET, "128.63.2.53", 53), True, False),
                 "i": resolver((socket.AF_INET, "192.36.148.17", 53), True, False),
                 "j": resolver((socket.AF_INET, "192.58.128.30", 53), True, False),
                 "k": resolver((socket.AF_INET, "193.0.14.129", 53), True, False),
                 "l": resolver((socket.AF_INET, "198.32.64.12", 53), True, False),
                 "m": resolver((socket.AF_INET, "202.12.27.33", 53), True, False)
                 }
rootres = multiresolver(rootresolvers.values())

default = sysres
