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

class DNNotIn(Exception):
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def __str__(self):
        return str(self.a) + " not in " + str(self.b)

class domainname:
    "A class for abstract representations of domain names"
    
    def __init__(self, parts, rooted):
        self.parts = parts
        self.rooted = rooted
    
    def __repr__(self):
        ret = ""
        if len(self.parts) > 0:
            for p in self.parts[:-1]:
                ret = ret + p + '.'
            ret = ret + self.parts[-1]
        if self.rooted:
            ret = ret + '.'
        return ret

    def __add__(self, y):
        if self.rooted:
            raise Exception("cannot append to a rooted domain name")
        return(domainname(self.parts + y.parts, y.rooted))

    def __getitem__(self, y):
        return domainname([self.parts[y]], self.rooted and (y == -1 or y == len(self.parts) - 1))

    def __getslice__(self, i, j):
        return domainname(self.parts[i:j], self.rooted and j >= len(self.parts))

    def __len__(self):
        return len(self.parts)

    def __eq__(self, y):
        if type(y) == str:
            y = fromstring(y)
        if self.rooted != y.rooted:
            return False
        if len(self.parts) != len(y.parts):
            return False
        for i in range(len(self.parts)):
            if self.parts[i].lower() != y.parts[i].lower():
                return False
        return True

    def __ne__(self, y):
        return not self.__eq__(y)
    
    def __contains__(self, y):
        if len(self) > len(y):
            return False
        if len(self) == 0:
            return self.rooted == y.rooted
        return y[-len(self):] == self

    def __sub__(self, y):
        if self not in y:
            raise DNNotIn(self, y)
        return self[:len(self) - len(y)]

    def __hash__(self):
        ret = 0
        for part in self.parts:
            ret = ret ^ hash(part)
        if self.rooted:
            ret = ret ^ -1
        return ret

    def canonwire(self):
        ret = ""
        for p in self.parts:
            ret += chr(len(p))
            ret += p.lower()
        ret += chr(0)
        return ret
    
class DNError(Exception):
    emptypart = 1
    illegalchar = 2
    def __init__(self, kind):
        self.kind = kind
    def __str__(self):
        return {1: "empty part",
                2: "illegal character"}[self.kind]

def fromstring(name):
    parts = []
    if name == ".":
        return domainname([], True)
    if name == "":
        return domainname([], False)
    while name.find('.') >= 0:
        cur = name.find('.')
        if cur == 0:
            raise DNError(DNError.emptypart)
        part = name[:cur]
        for c in part:
            if ord(c) < 33:
                raise DNError(DNError.illegalchar)
        parts.append(part)
        name = name[cur + 1:]
    if len(name) > 0:
        parts.append(name)
        rooted = False
    else:
        rooted = True
    return domainname(parts, rooted)

