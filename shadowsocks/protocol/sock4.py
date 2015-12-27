# -*- coding: utf-8 -*-
#14-6-3
# create by: snower

import sys
import logging
import struct
import socket
from protocol import Protocol,ProtocolParseEndError
import config

class Sock4Protocol(Protocol):
    def __init__(self,*args,**kwargs):
        super(Sock4Protocol,self).__init__(*args,**kwargs)

        self.local_addr = ''
        self.local_port = ''

    def parse(self,data):
        inet_ut = self.handle_cmd(data)
        self.parse_addr_info(data)
        self.request.write('\x00\x90%s%s' % (struct.pack(">H", self.local_port), socket.inet_aton(self.local_addr)))
        raise ProtocolParseEndError('', inet_ut)

    def handle_cmd(self, data):
        cmd = ord(data[1])
        if cmd == 0x01:
            self.local_addr = config.BIND_ADDR
            self.local_port = config.PORT
            return '\x01'
        self.request.end()
        raise Exception("sock4 unknown cmd %s", cmd)

    def parse_addr_info(self, data):
        self.remote_port, = struct.unpack('>H', data[2:4])
        self.remote_addr = socket.inet_ntoa(data[4:8])
        if self.remote_addr[:6] == "0.0.0.":
            data = data[8:]
            index = data.find('\x00')
            if index >= 0:
                data = data[index + 1:]
                index = data.find('\x00')
                self.remote_addr = data[:index]