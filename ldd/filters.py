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
import time
import fcntl
import struct

import server

def linuxifip4hack(ifname):
    req = ifname + ("\0" * (32 - len(ifname)))
    sk = socket.socket()
    res = fcntl.ioctl(sk.fileno(), 0x8915, req)
    sk.close()
    sockaddr = res[16:]
    return sockaddr[4:8]

class valuecache:
    def __init__(self, func, expire):
        self.func = func
        self.expire = expire
        self.last = 0

    def __call__(self, *args):
        now = int(time.time())
        if self.last == 0 or now - self.last > self.expire:
            self.val = self.func(*(args))
            self.last = now
        return self.val

class prefix6to4(server.handler):
    def __init__(self, next, v4addr):
        self.next = next
        if callable(v4addr):
            self.packed = v4addr
        elif len(v4addr) == 4:
            self.packed = v4addr
        else:
            self.packed = socket.inet_pton(socket.AF_INET, v4addr)

    def handle(self, *args):
        resp = self.next.handle(*args)
        if resp is None:
            return None
        for rr in resp.allrrs():
            if rr.head.istype("AAAA"):
                addr = rr.data["address"]
                if addr[0:6] == "\x20\x02\x00\x00\x00\x00":
                    packed = self.packed
                    if callable(packed):
                        packed = packed()
                    addr = addr[0:2] + packed + addr[6:]
                    rr.data["address"] = addr
        return resp

class addrfilter(server.handler):
    def __init__(self, default = None, matchers = []):
        self.matchers = matchers
        self.default = default

    def setdefault(self, handler):
        self.default = handler

    def addmatcher(self, af, prefix, preflen, handler):
        self.matchers += [(af, socket.inet_pton(af, prefix), preflen, handler)]
    
    def handle(self, query, pkt, origin):
        matchlen = -1
        match = self.default
        if pkt.addr is not None:
            for af, prefix, preflen, handler in self.matchers:
                if pkt.addr[0] == af:
                    addr = socket.inet_pton(af, pkt.addr[1])
                    bytes = preflen >> 3
                    restmask = 255 ^ ((1 << (8 - (preflen & 7))) - 1)
                    if prefix[0:bytes] == addr[0:bytes] and \
                           (ord(prefix[bytes]) & restmask) == (ord(addr[bytes]) & restmask):
                        if preflen > matchlen:
                            matchlen = preflen
                            match = handler
        if match is not None:
            return match.handle(query, pkt, origin)
        return None
