# -*- coding: utf-8 -*-
# 15/1/16
# create by: snower

import struct
import socket
from protocol import Protocol,ProtocolParseEndError

class RedirectProtocol(Protocol):
    def get_address(self):
        address_data = self.request.conn.getsockopt(socket.SOL_IP, 80, 16)
        self.remote_addr = socket.inet_ntoa(address_data[4:8])
        self.remote_port, = struct.unpack(">H", address_data[2:4])

    def parse(self, data):
        self.get_address()
        raise ProtocolParseEndError(data)