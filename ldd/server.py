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
import threading
import select
import errno
import logging
import time

import proto
import rec
import dn
import resolver

logger = logging.getLogger("ldd.server")

class dnsserver:
    class socklistener(threading.Thread):
        def __init__(self, server):
            threading.Thread.__init__(self)
            self.server = server
            self.alive = True

        class sender:
            def __init__(self, addr, sk):
                self.addr = addr
                self.sk = sk

            def send(self, pkt):
                logger.debug("sending response to %04x", pkt.qid)
                self.sk.sendto(pkt.encode(), self.addr)

        def run(self):
            while self.alive:
                p = select.poll()
                for af, sk in self.server.sockets:
                    p.register(sk.fileno(), select.POLLIN)
                try:
                    fds = p.poll(1000)
                except select.error, e:
                    if e[0] == errno.EINTR:
                        continue
                    raise
                for fd, event in fds:
                    if event & select.POLLIN == 0:
                        continue
                    for af, sk in self.server.sockets:
                        if sk.fileno() == fd:
                            break
                    else:
                        continue
                    req, addr = sk.recvfrom(65536)
                    try:
                        pkt = proto.decodepacket(req)
                    except proto.malformedpacket, inst:
                        resp = proto.packet(inst.qid, ["resp"])
                        resp.rescode = proto.FORMERR
                        sk.sendto(resp.encode(), addr)
                    else:
                        logger.debug("got request (%04x) from %s", pkt.qid, addr[0])
                        pkt.addr = (af,) + addr
                        self.server.queuereq(pkt, dnsserver.socklistener.sender(addr, sk))

        def stop(self):
            self.alive = False

    class dispatcher(threading.Thread):
        def __init__(self, server):
            threading.Thread.__init__(self)
            self.server = server
            self.alive = True

        def run(self):
            while self.alive:
                req = self.server.dequeuereq()
                if req is not None:
                    pkt, sender = req
                    resp = self.server.handle(pkt)
                    if resp is None:
                        resp = proto.responsefor(pkt, proto.SERVFAIL)
                    sender.send(resp)

    class queuemonitor(threading.Thread):
        def __init__(self, server):
            threading.Thread.__init__(self)
            self.server = server

        def run(self):
            while(self.server.running):
                self.server.queuelock.acquire()
                if len(self.server.queue) > 0:
                    peeked = self.server.queue[0]
                else:
                    peeked = None
                self.server.queuelock.release()
                if peeked is not None:
                    if time.time() - peeked[0] > 1:
                        newdsp = dnsserver.dispatcher(self.server)
                        self.server.dispatchers += [newdsp]
                        newdsp.start()
                        logger.debug("starting new dispatcher, there are now %i", len(self.server.dispatchers))
                time.sleep(1)

    def __init__(self):
        self.sockets = []
        self.queue = []
        self.zones = []
        self.listener = None
        self.dispatchers = []
        self.running = False
        self.queuelock = threading.Condition()
        self.knownkeys = []

    def handle(self, pkt):
        resp = None

        if len(self.knownkeys) > 0:
            import dnssec
            dnssec.tsigverify(pkt, self.knownkeys)
        
        for query in pkt.qlist:
            match = None
            for zone in self.zones:
                if query.name in zone.origin:
                    if match is None:
                        match = zone
                    elif len(zone.origin) > len(match.origin):
                        match = zone
            if match is None:
                return None
            else:
                curresp = match.handle(query, pkt)
                if resp is None:
                    resp = curresp
                else:
                    resp.merge(curresp)
        
        if resp is not None and resp.tsigctx is not None and not resp.signed:
            resp.tsigctx.signpkt(resp)

        return resp

    def addsock(self, af, socket):
        self.sockets += [(af, socket)]

    def addzone(self, zone):
        self.zones += [zone]

    def queuereq(self, req, sender):
        self.queuelock.acquire()
        self.queue += [(time.time(), req, sender)]
        logger.debug("queue length+: %i", len(self.queue))
        self.queuelock.notify()
        self.queuelock.release()

    def dequeuereq(self):
        self.queuelock.acquire()
        if len(self.queue) == 0:
            self.queuelock.wait()
        if len(self.queue) > 0:
            ret = self.queue[0]
            self.queue = self.queue[1:]
        else:
            ret = None
        logger.debug("queue length-: %i", len(self.queue))
        self.queuelock.release()
        if ret is None:
            return None
        else:
            return ret[1:]

    def start(self):
        if self.running:
            raise Exception("already running")
        lst = dnsserver.socklistener(self)
        self.listener = lst
        lst.start()
        for i in xrange(10):
            newdsp = dnsserver.dispatcher(self)
            self.dispatchers += [newdsp]
            newdsp.start()
        self.running = True
        self.monitor = dnsserver.queuemonitor(self)
        self.monitor.start()

    def stop(self):
        self.listener.stop()
        self.listener.join()
        self.listener = None
        for dsp in self.dispatchers:
            dsp.alive = False
        self.queuelock.acquire()
        self.queuelock.notifyAll()
        self.queuelock.release()
        for dsp in self.dispatchers + []:
            dsp.join()
            self.dispatchers.remove(dsp)
        self.running = False
        self.monitor = None

    def resolver(self, addr = None):
        class myres(resolver.resolver):
            def __init__(self, server, addr):
                self.server = server
                self.addr = addr
            def resolve(self, packet):
                if self.addr is not None:
                    packet.addr = self.addr
                packet.setflags(["internal"])
                return self.server.handle(packet)
        return myres(self, addr)

class zone:
    def __init__(self, origin, handler):
        if type(origin) == str:
            self.origin = dn.fromstring(origin)
            self.origin.rooted = True
        else:
            self.origin = origin
        self.handler = handler

    def handle(self, query, pkt):
        resp = self.handler.handle(query, pkt, self.origin)
        return resp

class authzone(zone):
    def __init__(self, aurecres, *args):
        self.aurecres = aurecres
        zone.__init__(self, *args)

    def handle(self, query, pkt):
        resp = zone.handle(self, query, pkt)
        if not "internal" in pkt.flags:
            if resp is None:
                resp = proto.responsefor(pkt)
                soa = zone.handle(self, rec.rrhead(self.origin, "SOA"), pkt)
                resp.aulist += soa.anlist
                resp.rescode = proto.NXDOMAIN
            else:
                resolver.resolvecnames(resp, self.aurecres)
                nsrecs = zone.handle(self, rec.rrhead(self.origin, "NS"), pkt)
                if nsrecs is not None:
                    resp.aulist += nsrecs.anlist
                    for rr in nsrecs.anlist:
                        resolver.resolveadditional(resp, rr, self.aurecres)
        else:
            if resp is None:
                return None
        resp.setflags(["auth"])
        return resp

class handler:
    def handle(self, query, pkt, origin):
        return None

class forwarder(handler):
    def __init__(self, nameserver, timeout = 2000, retries = 3):
        self.nameserver = nameserver
        self.timeout = timeout
        self.retries = retries
    
    def handle(self, query, pkt, origin):
        sk = socket.socket(self.nameserver[0], socket.SOCK_DGRAM)
        sk.bind(("", 0))
        p = select.poll()
        p.register(sk.fileno(), select.POLLIN)
        for i in range(self.retries):
            sk.sendto(pkt.encode(), self.nameserver[1:])
            fds = p.poll(self.timeout)
            if (sk.fileno(), select.POLLIN) in fds:
                break
        else:
            return None
        resp = sk.recv(65536)
        resp = proto.decodepacket(resp)
        return resp
    
class recurser(handler):
    def __init__(self, resolver):
        self.resolver = resolver

    def handle(self, query, pkt, origin):
        try:
            resp = self.resolver.resolve(pkt)
        except resolver.error:
            return None
        return resp

class chain(handler):
    def __init__(self, chain):
        self.chain = chain

    def add(self, handler):
        self.chain += [handler]
    
    def handle(self, *args):
        for h in self.chain:
            resp = h.handle(*args)
            if resp is not None:
                return resp
        return None

