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

ip4addr = "224.0.0.251"
ip6addr = "ff02::fb"

def mkip4sock(port = 5353):
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    mcastinfo = socket.inet_pton(socket.AF_INET, ip4addr)
    mcastinfo += socket.inet_pton(socket.AF_INET, "0.0.0.0")
    sk.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, mcastinfo)
    sk.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_TTL, 255)
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind(("", port))
    return sk

def mkip6sock(port = 5353):
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mcastinfo = socket.inet_pton(socket.AF_INET6, ip6addr)
    mcastinfo += struct.pack("I", 0)
    sk.setsockopt(socket.SOL_IP, socket.IPV6_JOIN_GROUP, mcastinfo)
    sk.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind(("", port))
    return sk
