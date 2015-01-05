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

    def parse(self,data):
        if self.stage == 0:
            self.hello(data)
        elif self.stage == 1:
            self.handle_cmd(data)
            self.parse_addr_info(data)
            raise ProtocolParseEndError(data[self.header_length:])

    def hello(self,data):
        self.request.write('\x05\00')
        self.stage = 1

    def handle_cmd(self, data):
        cmd = ord(data[1])
        if cmd == 0x01:
            self.request.write('\x05\x00\x00\x01\%s%s' % (socket.inet_aton(config.BIND_ADDR), struct.pack("!H", config.PORT)))
        elif cmd == 0x03:
            self.request.write('\x05\x00\x00\x01\%s%s' % (socket.inet_aton(config.BIND_ADDR), struct.pack("!H", config.PORT)))
        else:
            self.request.end()
            raise Exception("sock5 unknown cmd %s", cmd)

    def parse_addr_info(self,data):
        addr_type = ord(data[3])
        if addr_type == 1:
            self.remote_addr = socket.inet_ntoa(data[4:8])
            self.remote_port = data[8:10]
            self.header_length = 10
        elif addr_type == 4:
            self.remote_addr = socket.inet_ntop(data[4:20])
            self.remote_port = data[20:22]
            self.header_length = 22
        elif addr_type == 3:
            addr_len = ord(data[4])
            self.remote_addr = data[5:5 + addr_len]
            self.remote_port = data[5 + addr_len:5 + addr_len + 2]
            self.header_length = 5 + addr_len + 2
        else:
            raise Exception(data)
        self.remote_port = struct.unpack('>H', self.remote_port)[0]
        if not self.remote_addr or not self.remote_port:
            raise Exception(data)