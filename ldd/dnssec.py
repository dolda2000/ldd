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

import base64
import time
import struct
from Crypto.Hash import HMAC, MD5

import proto, rec, dn

class tsigkey:
    def __init__(self, name, algo, secret):
        if type(name) == str:
            self.name = dn.fromstring(name)
        else:
            self.name = name
        if type(algo) == str:
            self.algo = algobyname[algo]
        else:
            self.algo = algo
        self.secret = secret

    def sign(self, message):
        return self.algo.sign(self.secret, message)

class tsigalgo:
    def __init__(self, name, cname, function):
        self.name = name
        if type(cname) == str:
            self.cname = dn.fromstring(cname)
        else:
            self.cname = cname
        self.function = function

    def sign(self, secret, message):
        return self.function(secret, message)

class tsigctx:
    def __init__(self, key, pkt, sr):
        self.key = key
        self.prevmac = sr.data["mac"]
        self.error = 0

    def signpkt(self, pkt):
        tsigsign(pkt, None, ctx = self, error = self.error)

def tsigsign(pkt, key, stime = None, fudge = 300, error = 0, other = "", ctx = None):
    if stime is None: stime = int(time.time())
    msg = ""
    if ctx is not None:
        if key is None:
            key = ctx.key
        msg += struct.pack(">H", len(ctx.prevmac)) + ctx.prevmac
    msg += pkt.encode()
    msg += key.name.canonwire()
    msg += struct.pack(">HL", rec.CLASSANY, 0)
    msg += key.algo.cname.canonwire()
    msg += struct.pack(">Q", stime)[-6:]
    msg += struct.pack(">3H", fudge, error, len(other))
    msg += other
    digest = key.sign(msg)
    pkt.addad(rec.rr((key.name, "TSIG", rec.CLASSANY), 0, rec.rrdata("TSIG", key.algo.cname, stime, fudge, digest, pkt.qid, error, other)))
    pkt.signed = True

def tsigverify(pkt, keys, vertime = None):
    if vertime is None: vertime = int(time.time())
    if len(pkt.adlist) < 1:
        return proto.FORMERR
    sr = pkt.adlist[-1]
    pkt.adlist = pkt.adlist[:-1]
    if not sr.head.istype("TSIG") or sr.head.rclass != rec.CLASSANY:
        return proto.FORMERR
    for key in keys:
        if key.name == sr.head.name:
            break
    else:
        return proto.BADKEY
    if key.algo.cname != sr.data["algo"]:
        return proto.BADKEY

    pkt.tsigctx = ctx = tsigctx(key, pkt, sr)
    
    other = sr.data["other"]
    msg = pkt.encode()
    msg += key.name.canonwire()
    msg += struct.pack(">HL", rec.CLASSANY, 0)
    msg += key.algo.cname.canonwire()
    msg += struct.pack(">Q", sr.data["stime"])[-6:]
    msg += struct.pack(">3H", sr.data["fudge"], sr.data["err"], len(other))
    msg += other
    digest = key.sign(msg)
    if digest != sr.data["mac"]:
        pkt.tsigctx = proto.BADSIG
        return proto.BADSIG
    if vertime != 0:
        if abs(vertime - sr.data["stime"]) > sr.data["fudge"]:
            pkt.tsigctx = proto.BADTIME
            return proto.BADTIME
    return key

def signhmacmd5(secret, message):
    s = HMAC.HMAC(secret, digestmod = MD5)
    s.update(message)
    return s.digest()

def readkeys(keyfile):
    close = False
    if type(keyfile) == str:
        keyfile = open(keyfile, "r")
        close = True
    try:
        ret = []
        for line in keyfile:
            words = line.split()
            if len(words) < 3:
                continue
            ret += [tsigkey(dn.fromstring(words[0]), words[1], base64.b64decode(words[2]))]
        return ret
    finally:
        if close: keyfile.close()

algos = [tsigalgo("hmac-md5", "hmac-md5.sig-alg.reg.int.", signhmacmd5)]

algobyname = dict([(a.name, a) for a in algos])
