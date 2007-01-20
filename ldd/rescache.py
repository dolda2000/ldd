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

import threading
import time

import resolver
import proto
import rec

class nxdmark:
    def __init__(self, expire, auth):
        self.expire = expire
        self.auth = auth

class cacheresolver(resolver.resolver):
    def __init__(self, resolver):
        self.resolver = resolver
        self.cache = dict()
        self.cachelock = threading.Lock()

    def getcached(self, name, rtype = proto.QTANY):
        self.cachelock.acquire()
        try:
            if name not in self.cache:
                return []
            now = int(time.time())
            if isinstance(self.cache[name], nxdmark):
                if self.cache[name].expire < now:
                    self.cache[name] = []
                    return []
                return self.cache[name]
            ret = []
            if rtype == proto.QTANY:
                cond = lambda rt: True
            elif type(rtype) == int:
                cond = lambda rt: rtype == rt
            elif type(rtype) == str:
                rtid = rec.rtypebyname(rtype)
                cond = lambda rt: rtid == rt
            else:
                rtset = set([((type(rtid) == str) and rec.rtypebyname(rtid)) or rtid for rtid in rtype])
                cond = lambda rt: rt in rtset
            for exp, trd, data, auth in self.cache[name]:
                if exp > now and cond(trd):
                    ret += [(rec.rr((name, trd), exp - now, data), auth)]
            return ret
        finally:
            self.cachelock.release()

    def dolookup(self, name, rtype):
        try:
            res = self.resolver.squery(name, rtype)
        except resolver.servfail, resolver.unreachable:
            return None
        if res is None:
            return None
        if res.rescode == proto.NXDOMAIN:
            ttl = 300
            for rr in res.aulist:
                if rr.head.istype("SOA"):
                    ttl = rr.data["minttl"]
            nc = nxdmark(int(time.time()) + ttl, res.aulist)
            self.cachelock.acquire()
            try:
                self.cache[name] = nc
            finally:
                self.cachelock.release()
            return nc
        now = int(time.time())
        self.cachelock.acquire()
        try:
            alltypes = set([rr.head.rtype for rr in res.allrrs()])
            for name in set([rr.head.name for rr in res.allrrs()]):
                if name in self.cache:
                    self.cache[name] = [cl for cl in self.cache[name] if cl[1] not in alltypes]
            for rr in res.allrrs():
                if rr.head.name not in self.cache:
                    self.cache[rr.head.name] = []
                self.cache[rr.head.name] += [(now + rr.ttl, rr.head.rtype, rr.data, [rr for rr in res.aulist if rr.head.istype("NS")])]
            return res
        finally:
            self.cachelock.release()

    def addcached(self, packet, cis):
        for item, auth in cis:
            packet.addan(item)
            for ns in auth:
                packet.addau(ns)
                nsal = self.getcached(ns.data["nsname"], ["A", "AAAA"])
                if type(nsal) == list:
                    for item, auth in nsal:
                        packet.addad(item)

    def resolve(self, packet):
        res = proto.responsefor(packet)
        for q in packet.qlist:
            name = q.name
            rtype = q.rtype
            while True:
                cis = self.getcached(name, rtype)
                if isinstance(cis, nxdmark):
                    if len(packet.qlist) == 1:
                        res.rescode = proto.NXDOMAIN
                        res.aulist = cis.auth
                        return res
                    continue
                if len(cis) == 0:
                    cics = self.getcached(name, "CNAME")
                    if isinstance(cics, nxdmark):
                        break
                    if len(cics) > 0:
                        self.addcached(res, cics)
                        name = cics[0][0].data["priname"]
                        continue
                break
            if len(cis) == 0:
                tres = self.dolookup(name, rtype)
                if isinstance(tres, nxdmark) and len(packet.qlist) == 1:
                    res.rescode = proto.NXDOMAIN
                    res.aulist = tres.auth
                    return res
                if tres is None and len(packet.qlist) == 1:
                    res.rescode = proto.SERVFAIL
                    return res
                if tres is not None and tres.rescode == 0:
                    res.merge(tres)
            else:
                self.addcached(res, cis)
        return res
