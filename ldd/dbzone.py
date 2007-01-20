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

import bsddb
import threading
import pickle
import logging

import server
import proto
import rec
import dn

logger = logging.getLogger("ldd.dbzone")

class dnsdb:
    def __init__(self, dbdir, dbfile):
        self.env = bsddb.db.DBEnv()
        self.env.open(dbdir, bsddb.db.DB_JOINENV | bsddb.db.DB_THREAD)
        self.db = bsddb.db.DB()
        self.db.open(dbdir + "/" + dbfile, flags = bsddb.db.DB_THREAD)

    def create(self, dbdir, dbfile):
        env = bsddb.db.DBEnv()
        env.open(dbdir, bsddb.db.DB_CREATE | bsddb.db.DB_EXCL | bsddb.db.DB_INIT_MPOOL | bsddb.db.DB_INIT_CDB | bsddb.db.DB_THREAD)
        db = bsddb.db.DB()
        db.open(dbdir + "/" + dbfile, dbtype = bsddb.db.DB_HASH, flags = bsddb.db.DB_CREATE | bsddb.db.DB_EXCL | bsddb.db.DB_THREAD)
        db.close()
        env.close()
    create = classmethod(create)

    def close(self):
        self.db.close()
        self.env.close()

    def decoderecord(self, name, record):
        set = pickle.loads(record)
        rrset = []
        for cur in set:
            head = rec.rrhead(name, cur[0])
            data = cur[2]
            newrr = rec.rr(head, cur[1], data)
            newrr.setflags(cur[3])
            rrset += [newrr]
        return rrset

    def encoderecord(self, rrset):
        set = []
        for rr in rrset:
            set += [(rr.head.rtype, rr.ttl, rr.data, rr.flags)]
        return pickle.dumps(set)

    def lookup(self, name):
        record = self.db.get(str(name))
        if record is None:
            return None
        return self.decoderecord(name, record)

    def set(self, name, rrset):
        self.db.put(str(name), self.encoderecord(rrset))
        return True
    
    def hasname(self, name):
        record = self.db.get(str(name))
        return record is not None

    def rmname(self, name):
        try:
            self.db.delete(str(name))
        except bsddb.db.DBNotFoundError:
            return False
        return True

    def rmrtype(self, name, rtype):
        if type(rtype) == str:
            rtype = rec.rtypebyname(rtype)
        rrset = self.lookup(name)
        if rrset is None:
            return False
        for rr in rrset:
            if rr.head.rtype == rtype:
                rrset.remove(rr)
        self.set(name, rrset)
        return True

    def addrr(self, name, rr):
        rrset = self.lookup(name)
        if rrset is None:
            rrset = []
        rrset += [rr]
        self.set(name, rrset)
        return True

    def listnames(self):
        cursor = self.db.cursor()
        ret = cursor.first()
        if ret is not None:
            name, record = ret
            yield name
            while True:
                ret = cursor.next()
                if ret is None:
                    break
                name, record = ret
                yield name
        cursor.close()

def rootify(rrset, origin):
    for rr in rrset:
        if not rr.head.name.rooted:
            rr.head.name += origin
        for dname, dval in rr.data.rdata.items():
            if isinstance(dval, dn.domainname) and not dval.rooted:
                rr.data.rdata[dname] += origin

class dbhandler(server.handler):
    def __init__(self, dbdir, dbfile):
        self.db = dnsdb(dbdir, dbfile)
        self.doddns = False
        self.authkeys = []

    def handle(self, query, pkt, origin):
        resp = proto.responsefor(pkt)
        if pkt.opcode == proto.QUERY:
            rrset = self.db.lookup(query.name)
            if rrset is None and query.name in origin:
                rrset = self.db.lookup(query.name - origin)
            if rrset is None:
                return None
            rootify(rrset, origin)
            resp.anlist = [rr for rr in rrset if rr.head.rtype == query.rtype or rr.head.istype("CNAME")]
            return resp
        if pkt.opcode == proto.UPDATE:
            logger.debug("got DDNS request")
            if len(pkt.qlist) != 1 or not pkt.qlist[0].istype("SOA"):
                resp.rescode = proto.FORMERR
                return resp
            if pkt.qlist[0].name != origin:
                resp.rescode = proto.NOTAUTH
                return resp

            # Check prerequisites
            for rr in pkt.anlist:
                if rr.ttl != 0:
                    resp.rescode = proto.FORMERR
                    return resp
                if rr.head.name not in origin:
                    resp.rescode = proto.NOTZONE
                    return resp
                myname = rr.head.name - origin
                rrset = self.db.lookup(myname)
                if rr.head.rclass == rec.CLASSANY:
                    if rr.data is not None:
                        resp.rescode = proto.FORMERR
                        return resp
                    if rr.head.rtype == proto.QTANY:
                        if rrset is None:
                            resp.rescode = proto.NXDOMAIN
                            return resp
                    else:
                        if rrset is not None:
                            for rr2 in rrset:
                                if rr2.head.name == myname and rr.head.rtype == rr2.head.rtype:
                                    break
                            else:
                                resp.rescode = proto.NXRRSET
                                return resp
                elif rr.head.rclass == rec.CLASSNONE:
                    if rr.data is not None:
                        resp.rescode = proto.FORMERR
                        return resp
                    if rr.head.rtype == proto.QTANY:
                        if rrset is not None:
                            resp.rescode = proto.YXDOMAIN
                            return resp
                    else:
                        if rrset is not None:
                            for rr2 in rrset:
                                if rr2.head.name == myname and rr.head.rtype == rr2.head.rtype:
                                    resp.rescode = proto.YXRRSET
                                    return resp
                elif rr.head.rclass == rec.CLASSIN:
                    if rrset is not None:
                        for rr2 in rrset:
                            if rr2.head.name == myname and rr.head.rtype == rr2.head.rtype and rr.data == rr2.data:
                                break
                        else:
                            resp.rescode = proto.NXRRSET
                            return resp
                else:
                    resp.rescode = FORMERR
                    return resp

            # Check for permission
            if not self.doddns:
                resp.rescode = proto.REFUSED
                return resp
            if type(self.authkeys) == list:
                if pkt.tsigctx is None:
                    resp.rescode = proto.REFUSED
                    return resp
                if pkt.tsigctx.error != 0:
                    resp.rescode = proto.NOTAUTH
                    return resp
                if pkt.tsigctx.key not in self.authkeys:
                    resp.rescode = proto.REFUSED
                    return resp
            elif type(self.authkeys) == None:
                authorized = True

            # Do precheck on updates
            for rr in pkt.aulist:
                if rr.head.name not in origin:
                    resp.rescode = proto.NOTZONE
                    return resp
                if rr.head.rclass == rec.CLASSIN:
                    if rr.head.rtype == proto.QTANY or rr.data is None:
                        resp.rescode = proto.FORMERR
                        return resp
                elif rr.head.rclass == rec.CLASSANY:
                    if rr.data is not None:
                        resp.rescode = proto.FORMERR
                        return resp
                elif rr.head.rclass == rec.CLASSNONE:
                    if rr.head.rtype == proto.QTANY or rr.ttl != 0 or rr.data is None:
                        resp.rescode = proto.FORMERR
                        return resp
                else:
                    resp.rescode = proto.FORMERR
                    return resp

            # Perform updates
            for rr in pkt.aulist:
                myname = rr.head.name - origin
                if rr.head.rclass == rec.CLASSIN:
                    logger.info("adding rr (%s)", rr)
                    self.db.addrr(myname, rr)
                elif rr.head.rclass == rec.CLASSANY:
                    if rr.head.rtype == proto.QTANY:
                        logger.info("removing rrset (%s)", rr.head.name)
                        self.db.rmname(myname)
                    else:
                        logger.info("removing rrset (%s, %s)", rr.head.name, rr.head.rtype)
                        self.db.rmrtype(myname, rr.head.rtype)
                elif rr.head.rclass == rec.CLASSNONE:
                    logger.info("removing rr (%s)", rr)
                    rrset = self.db.lookup(myname)
                    changed = False
                    if rrset is not None:
                        for rr2 in rrset:
                            if rr2.head == rr.head and rr2.data == rr.data:
                                rrset.remove(rr2)
                                changed = True
                        self.db.set(myname, rrset)

            return resp
            
        resp.rescode = proto.NOTIMP
        return resp
