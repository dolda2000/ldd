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
import struct

import proto
import dn

rtypes = []

def addrtype(id, name, syntax):
    rtypes.append((id, name, syntax))

def rtypebyid(id):
    for rtype in rtypes:
        if rtype[0] == id:
            return rtype
    return None

def rtypebyname(name):
    for rtype in rtypes:
        if rtype[1] == name.upper():
            return rtype[0]
    return None

class error(Exception):
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text

class malformedrr(Exception):
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text

class rrhead:
    def __init__(self, name = None, rtype = None, rclass = None):
        if rclass is None: rclass = CLASSIN
        if type(name) == str:
            self.name = dn.fromstring(name)
        else:
            self.name = name
        if type(rtype) == str:
            self.rtype = rtypebyname(rtype)
            if self.rtype is None:
                raise error("no such rtype " + rtype)
        else:
            self.rtype = rtype
        self.rclass = rclass

    def encode(self, names, offset):
        ret, names = proto.encodename(self.name, names, offset)
        ret += struct.pack(">HH", self.rtype, self.rclass)
        return ret, names

    def __eq__(self, other):
        return self.name == other.name and self.rtype == other.rtype

    def __str__(self):
        rtype = rtypebyid(self.rtype)
        if rtype is None:
            return "%02x RRhead %s" % (self.rtype, self.name)
        else:
            return "%s RRhead %s" % (rtype[1], self.name)

    def istype(self, rtype):
        if type(rtype) == str:
            rtype = rtypebyname(rtype)
        return self.rtype == rtype
        
    def decode(self, packet, offset):
        name, offset = proto.decodename(packet, offset)
        rtype, rclass = struct.unpack(">HH", packet[offset:offset + struct.calcsize(">HH")])
        offset += struct.calcsize(">HH")
        ret = rrhead(name, rtype, rclass)
        return ret, offset
    decode = classmethod(decode)

class rrdata:
    def __init__(self, rtype, *args):
        if type(rtype) == tuple and type(args[0]) == dict:
            self.rtype = rtype
            self.rdata = args[0]
            return
        
        if type(rtype) == str:
            self.rtype = rtypebyname(rtype)
            if self.rtype is None:
                raise error("no such rtype " + rtype)
        else:
            self.rtype = rtype
        rtid = self.rtype
        self.rtype = rtypebyid(rtid)
        if self.rtype is None:
            raise error("no such rtype " + rtid)
        self.rdata = {}
        for i, e in enumerate(self.rtype[2]):
            d = self.convdata(e[0], args[i])
            self.rdata[e[1]] = d

    def __eq__(self, other):
        return(self.rdata == other.rdata)

    def __str__(self):
        ret = "{"
        first = True
        for e in self.rtype[2]:
            if not first:
                ret += ", "
            first = False
            ret += e[1] + ": "
            d = self.rdata[e[1]]
            if e[0] == "4":
                ret += socket.inet_ntop(socket.AF_INET, d)
            elif e[0] == "6":
                ret += socket.inet_ntop(socket.AF_INET6, d)
            elif e[0] == "s":
                ret += '"' + d + '"'
            else:
                ret += str(d)
        ret += "}"
        return ret

    def istype(self, rtype):
        if type(rtype) == str:
            rtype = rtypebyname(rtype)
        return self.rtype[0] == rtype
        
    def convdata(self, dtype, data):
        if dtype == "4":
            if type(data) != str:
                raise error("IPv4 address must be a string")
            if len(data) == 4:
                d = data
            else:
                d = socket.inet_pton(socket.AF_INET, data)
        if dtype == "6":
            if type(data) != str:
                raise error("IPv6 address must be a string")
            if len(data) == 16 and data.find(":") == -1:
                d = data
            else:
                d = socket.inet_pton(socket.AF_INET6, data)
        if dtype == "d":
            if type(data) == str:
                d = dn.fromstring(data)
            elif isinstance(data, dn.domainname):
                d = data
            else:
                raise error("Domain name must be either proper or string")
        if dtype == "s":
            d = str(data)
        if dtype == "i":
            d = int(data)
        return d
    
    def __iter__(self):
        return iter(self.rdata)
    
    def __getitem__(self, i):
        return self.rdata[i]

    def __setitem__(self, i, v):
        for e in self.rtype[2]:
            if e[1] == i:
                break
        else:
            raise error("No such data for " + self.rtype[1] + " record: " + str(i))
        self.rdata[i] = self.convdata(e[0], v)

    def encode(self, names, offset):
        ret = ""
        for e in self.rtype[2]:
            d = self.rdata[e[1]]
            if e[2] == "strc":
                ret += d
                offset += len(d)
            if e[2] == "cmdn":
                buf, names = proto.encodename(d, names, offset)
                ret += buf
                offset += len(buf)
            if e[2] == "lstr":
                ret += chr(len(d)) + d
                offset += 1 + len(d)
            if e[2] == "llstr":
                ret += struct.pack(">H", len(d)) + d
                offset += struct.calcsize(">H") + len(d)
            if e[2] == "short":
                ret += struct.pack(">H", d)
                offset += struct.calcsize(">H")
            if e[2] == "long":
                ret += struct.pack(">L", d)
                offset += struct.calcsize(">L")
            if e[2] == "int6":
                ret += struct.pack(">Q", d)[-6:]
                offset += 6
        return ret, names

    def decode(self, rtid, packet, offset, dlen):
        rtype = rtypebyid(rtid)
        origoff = offset
        rdata = {}
        if rtype is None:
            rtype = (rtid, "Unknown", [("s", "unknown", "strc", dlen)])
        for e in rtype[2]:
            if e[2] == "strc":
                d = packet[offset:offset + e[3]]
                offset += e[3]
            if e[2] == "cmdn":
                d, offset = proto.decodename(packet, offset)
            if e[2] == "lstr":
                dl = ord(packet[offset])
                offset += 1
                d = packet[offset:offset + dl]
                offset += dl
            if e[2] == "llstr":
                (dl,) = struct.unpack(">H", packet[offset:offset + struct.calcsize(">H")])
                offset += struct.calcsize(">H")
                d = packet[offset:offset + dl]
                offset += dl
            if e[2] == "short":
                (d,) = struct.unpack(">H", packet[offset:offset + struct.calcsize(">H")])
                offset += struct.calcsize(">H")
            if e[2] == "long":
                (d,) = struct.unpack(">L", packet[offset:offset + struct.calcsize(">L")])
                offset += struct.calcsize(">L")
            if e[2] == "int6":
                (d,) = struct.unpack(">Q", ("\0" * (struct.calcsize(">Q") - 6)) + packet[offset:offset + 6])
                offset += 6
            rdata[e[1]] = d
        if origoff + dlen != offset:
            raise malformedrr(rtype[1] + " RR data length mismatch")
        return rrdata(rtype, rdata)
    decode = classmethod(decode)

class rr:
    def __init__(self, head, ttl, data):
        if type(head) == tuple:
            self.head = rrhead(*head)
        else:
            self.head = head
        self.ttl = ttl
        self.data = data
        self.flags = set()

    def setflags(self, flags):
        self.flags |= set(flags)

    def clrflags(self, flags):
        self.flags -= set(flags)
    
    def encode(self, names, offset):
        ret, names = self.head.encode(names, offset)
        if self.data is None:
            data = ""
        else:
            data, names = self.data.encode(names, offset + len(ret) + struct.calcsize(">LH"))
        ret += struct.pack(">LH", self.ttl, len(data))
        ret += data
        return ret, names

    def __eq__(self, other):
        return self.head == other.head and self.ttl == other.ttl and self.data == other.data

    def __str__(self):
        rtype = rtypebyid(self.head.rtype)
        if rtype is None:
            ret = "%02x" % self.head.rtype
        else:
            ret = rtype[1]
        ret += " RR %s, TTL=%i: %s" % (self.head.name, self.ttl, self.data)
        if len(self.flags) > 0:
            ret += " (Flags:"
            for f in self.flags:
                ret += " " + f
            ret += ")"
        return ret
    
    def decode(self, packet, offset):
        head, offset = rrhead.decode(packet, offset)
        ttl, dlen = struct.unpack(">LH", packet[offset:offset + struct.calcsize(">LH")])
        offset += struct.calcsize(">LH")
        if dlen == 0:
            data = None
        else:
            data = rrdata.decode(head.rtype, packet, offset, dlen)
            offset += dlen
        return rr(head, ttl, data), offset
    decode = classmethod(decode)

addrtype(0x01, "A", [("4", "address", "strc", 4)])
addrtype(0x02, "NS", [("d", "nsname", "cmdn")])
addrtype(0x05, "CNAME", [("d", "priname", "cmdn")])
addrtype(0x06, "SOA", [("d", "priserv", "cmdn"),
                       ("d", "mailbox", "cmdn"),
                       ("i", "serial", "long"),
                       ("i", "refresh", "long"),
                       ("i", "retry", "long"),
                       ("i", "expire", "long"),
                       ("i", "minttl", "long")])
addrtype(0x0c, "PTR", [("d", "target", "cmdn")])
addrtype(0x0f, "MX", [("i", "prio", "short"),
                      ("d", "target", "cmdn")])
addrtype(0x10, "TXT", [("s", "rrtext", "lstr")])
addrtype(0x1c, "AAAA", [("6", "address", "strc", 16)])
addrtype(0x21, "SRV", [("i", "prio", "short"),
                       ("i", "weight", "short"),
                       ("i", "port", "short"),
                       ("d", "target", "cmdn")])
addrtype(0xfa, "TSIG", [("d", "algo", "cmdn"),
                        ("i", "stime", "int6"),
                        ("i", "fudge", "short"),
                        ("s", "mac", "llstr"),
                        ("i", "orgid", "short"),
                        ("i", "err", "short"),
                        ("s", "other", "llstr")])

CLASSIN = 1
CLASSCS = 2
CLASSCH = 3
CLASSHS = 4
CLASSNONE = 254
CLASSANY = 255
