# -*- coding: utf-8 -*-
#14-6-3
# create by: snower

import sys
import logging
import struct
import socket
from protocol import Protocol,ProtocolParseEndError
import config

class Sock5Protocol(Protocol):
    def __init__(self,*args,**kwargs):
        super(Sock5Protocol,self).__init__(*args,**kwargs)

        self.stage=0
        self.header_length=0
        self.local_addr = ''
        self.local_port = ''

    def parse(self,data):
        if self.stage == 0:
            self.hello(data)
        elif self.stage == 1:
            inet_ut = self.handle_cmd(data)
            self.parse_addr_info(data)
            self.request.write('\x05\x00\x00\x01%s%s' % (socket.inet_aton(self.local_addr), struct.pack(">H", self.local_port)))
            raise ProtocolParseEndError(data[self.header_length:], inet_ut)

    def hello(self,data):
        self.request.write('\x05\00')
        self.stage = 1

    def handle_cmd(self, data):
        cmd = ord(data[1])
        if cmd == 0x01:
            self.local_addr = config.BIND_ADDR
            self.local_port = config.PORT
            return '\x01'
        if cmd == 0x03:
            self.local_addr = config.BIND_ADDR
            self.local_port = config.PORT
            return '\x02'
        self.request.end()
        raise Exception("sock5 unknown cmd %s", cmd)

    def parse_addr_info(self,data):
        addr_type = ord(data[3])
        if addr_type == 1:
            self.remote_addr = socket.inet_ntoa(data[4:8])
            self.remote_port = data[8:10]
            self.header_length = 10
        elif addr_type == 4:
            self.remote_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
            self.remote_port = data[20:22]
            self.header_length = 22
        elif addr_type == 3:
            addr_len = ord(data[4])
            self.remote_addr = data[5:5 + addr_len]
            self.remote_port = data[5 + addr_len:5 + addr_len + 2]
            self.header_length = 5 + addr_len + 2
        else:
            raise Exception(data)
        self.remote_port, = struct.unpack('>H', self.remote_port)

    def unpack_udp(self, data):
        addr_type = ord(data[3])
        if addr_type == 1:
            remote_addr = socket.inet_ntoa(data[4:8])
            remote_port = data[8:10]
            header_length = 10
        elif addr_type == 4:
            remote_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
            remote_port = data[20:22]
            header_length = 22
        elif addr_type == 3:
            addr_len = ord(data[4])
            remote_addr = data[5:5 + addr_len]
            remote_port = data[5 + addr_len:5 + addr_len + 2]
            header_length = 5 + addr_len + 2
        else:
            raise Exception(data)
        remote_port, = struct.unpack('>H', remote_port)
        return remote_addr, remote_port, data[header_length:]

    def pack_udp(self, remote_addr, remote_port, data):
        header = '\x00\x00\x00'
        addrinfo = socket.getaddrinfo(remote_addr)
        if addrinfo[0] == 2:
            return "".join([header, struct.pack(">B", 1), socket.inet_aton(remote_addr), struct.pack(">H", remote_port), data])
        if addrinfo[0] == 30:
            return "".join([header, struct.pack(">B", 4), socket.inet_pton(socket.AF_INET6, remote_addr), struct.pack(">H", remote_port), data])
        return "".join([header, struct.pack(">BB", 4, len(remote_addr)), remote_addr, struct.pack(">H", remote_port), data])