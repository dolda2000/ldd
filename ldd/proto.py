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

from random import randint
import struct

import dn
import rec

class malformedpacket(Exception):
    def __init__(self, text, qid):
        self.text = text
        self.qid = qid

    def __str__(self):
        return self.text

class packet:
    "An abstract representation of a DNS query"

    def __init__(self, qid = None, flags = 0, addr = None):
        if qid is None: qid = randint(0, 65535)
        self.qid = qid
        self.qlist = []
        self.anlist = []
        self.aulist = []
        self.adlist = []
        self.opcode = 0
        self.rescode = 0
        self.addr = addr
        self.signed = False
        self.tsigctx = None
        if type(flags) == int:
            self.initflags(flags)
        elif type(flags) == set:
            self.flags = flags
        else:
            self.flags = set(flags)
        
    def setflags(self, flags):
        flags = set(flags)
        self.flags |= flags

    def clrflags(self, flags):
        flags = set(flags)
        self.flags -= flags

    def initflags(self, flags):
        nf = set()
        if flags & 0x8000: nf.add("resp")
        if flags & 0x0400: nf.add("auth")
        if flags & 0x0200: nf.add("trunc")
        if flags & 0x0100: nf.add("recurse")
        if flags & 0x0080: nf.add("recursed")
        if flags & 0x0020: nf.add("isauthen")
        if flags & 0x0010: nf.add("authok")
        self.opcode =   (flags & 0x7800) >> 11
        self.rescode =   flags & 0x000f
        self.flags = nf

    def encodeflags(self):
        ret = 0
        if "resp"     in self.flags: ret |= 0x8000
        if "auth"     in self.flags: ret |= 0x0400
        if "trunc"    in self.flags: ret |= 0x0200
        if "recurse"  in self.flags: ret |= 0x0100
        if "recursed" in self.flags: ret |= 0x0080
        if "authok"   in self.flags: ret |= 0x0010
        ret |= self.opcode << 11
        ret |= self.rescode
        return ret

    def addq(self, rr):
        self.qlist.append(rr)

    def addan(self, rr):
        for rr2 in self.anlist:
            if rr2.head  == rr.head and rr2.data == rr.data:
                break
        else:
            self.anlist.append(rr)

    def addau(self, rr):
        for rr2 in self.aulist:
            if rr2.head  == rr.head and rr2.data == rr.data:
                break
        else:
            self.aulist.append(rr)

    def addad(self, rr):
        for rr2 in self.adlist:
            if rr2.head  == rr.head and rr2.data == rr.data:
                break
        else:
            self.adlist.append(rr)

    def allrrs(self):
        return self.anlist + self.aulist + self.adlist

    def merge(self, other):
        for lst in ["anlist", "aulist", "adlist"]:
            for rr in getattr(other, lst):
                for rr2 in getattr(self, lst):
                    if rr2.head == rr.head and rr2.data == rr.data:
                        break
                else:
                    getattr(self, lst).append(rr)
    
    def getanswer(self, name, rtype):
        for rr in self.anlist + self.aulist + self.adlist:
            if rr.head.istype(rtype) and rr.head.name == name:
                return rr
        return None

    def hasanswers(self):
        for q in self.qlist:
            for rr in self.anlist + self.aulist + self.adlist:
                if rr.head.rtype == q.rtype and rr.head.name == q.name:
                    break
                if rr.head.istype("CNAME") and rr.head.name == q.name and self.getanswer(rr.data["priname"], q.rtype) is not None:
                    break
            else:
                break
        else:
            return True
        return False
        
    def __str__(self):
        ret = ""
        ret += "ID: " + str(self.qid) + "\n"
        ret += "Flags: " + str(self.flags) + "\n"
        ret += "Opcode: " + str(self.opcode) + "\n"
        ret += "Resp. code: " + str(self.rescode) + "\n"
        ret += "Queries:\n"
        for rr in self.qlist:
            ret += "\t" + str(rr) + "\n"
        ret += "Answers:\n"
        for rr in self.anlist:
            ret += "\t" + str(rr) + "\n"
        ret += "Auth RRs:\n"
        for rr in self.aulist:
            ret += "\t" + str(rr) + "\n"
        ret += "Additional RRs:\n"
        for rr in self.adlist:
            ret += "\t" + str(rr) + "\n"
        return ret

    def encode(self):
        ret = ""
        ret += struct.pack(">6H", self.qid, self.encodeflags(), len(self.qlist), len(self.anlist), len(self.aulist), len(self.adlist))
        offset = len(ret)
        names = []
        for rr in self.qlist:
            rre, names = rr.encode(names, offset)
            offset += len(rre)
            ret += rre
        for rr in self.anlist:
            rre, names = rr.encode(names, offset)
            offset += len(rre)
            ret += rre
        for rr in self.aulist:
            rre, names = rr.encode(names, offset)
            offset += len(rre)
            ret += rre
        for rr in self.adlist:
            rre, names = rr.encode(names, offset)
            offset += len(rre)
            ret += rre
        return ret

def decodepacket(string):
    offset = struct.calcsize(">6H")
    qid, flags, qno, anno, auno, adno = struct.unpack(">6H", string[0:offset])
    ret = packet(qid, flags)
    try:
        for i in range(qno):
            crr, offset = rec.rrhead.decode(string, offset)
            ret.addq(crr)
        for i in range(anno):
            crr, offset = rec.rr.decode(string, offset)
            ret.addan(crr)
        for i in range(auno):
            crr, offset = rec.rr.decode(string, offset)
            ret.addau(crr)
        for i in range(adno):
            crr, offset = rec.rr.decode(string, offset)
            ret.addad(crr)
    except rec.malformedrr, inst:
        raise malformedpacket(str(inst), qid)
    return ret

def responsefor(pkt, rescode = 0):
    resp = packet(pkt.qid, ["resp"])
    resp.opcode = pkt.opcode
    resp.rescode = rescode
    resp.tsigctx = pkt.tsigctx
    resp.qlist = pkt.qlist + []  # Make a copy
    return resp

def decodename(packet, offset):
    parts = []
    while True:
        clen = ord(packet[offset])
        offset += 1
        if clen & 0xc0:
            my = dn.domainname(parts, False)
            cont, = struct.unpack(">H", chr(clen & 0x3f) + packet[offset])
            res, discard = decodename(packet, cont)
            return my + res, offset + 1
        elif clen == 0:
            return dn.domainname(parts, True), offset
        else:
            parts.append(packet[offset:offset + clen])
            offset += clen

def encodename(dn, names, offset):
    ret = ""
    for i in range(len(dn)):
        for name, off in names:
            if name == dn[i:]:
                ret += chr(0xc0 + (off >> 8))
                ret += chr(off & 0xff)
                offset += 2
                return ret, names
        if offset < 16384:
            names += [(dn[i:], offset)]
        ret += chr(len(dn.parts[i]))
        ret += dn.parts[i]
        offset += 1 + len(dn.parts[i])
    ret += chr(0)
    offset += 1
    return ret, names

# Opcode constants
QUERY = 0
IQUERY = 1
STATUS = 2
UPDATE = 5

# Response code constants
#  RFC 1035:
FORMERR = 1
SERVFAIL = 2
NXDOMAIN = 3
NOTIMP = 4
REFUSED = 5
#  RFC 2136:
YXDOMAIN = 6
YXRRSET = 7
NXRRSET = 8
NOTAUTH = 9
NOTZONE = 10
#  RFC 2845:
BADSIG = 16
BADKEY = 17
BADTIME = 18

# Special RR types
QTANY = 255
QTMAILA = 254
QTMAILB = 253
QTAXFR = 252
