#!/usr/bin/env python

# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import with_statement
import sys
import os
os.chdir(os.path.dirname(__file__) or '.')
import random
import time
import struct
import sevent
import logging
import traceback
from utils import *
from protocol import ProtocolParseEndError
from protocol.http import HttpProtocol
from protocol.sock5 import Sock5Protocol
from protocol.redirect import RedirectProtocol
from protocol.ss import SSProtocol
from xstream.client import Client
from rule import Rule
import config

class PassResponse(object):
    def __init__(self, request):
        self.conn = sevent.tcp.Socket()
        self.request = request
        self.is_connected=False
        self.buffer=[]
        self.time=time.time()
        self.stream = None

        self.conn.on('connect', self.on_connect)
        self.conn.on('data', self.on_data)
        self.conn.on('close', self.on_close)
        self.conn.on('end', self.on_end)
        self.conn.connect((self.request.protocol.remote_addr,self.request.protocol.remote_port),30)

    def on_connect(self, s):
        self.is_connected=True
        for b in self.buffer:
            self.write(b)

    def on_data(self, s, data):
        self.request.write(data)

    def on_close(self, s):
        self.request.end()

    def on_end(self, s):
        pass

    def write(self,data):
        if not data:return
        if self.is_connected:
            self.conn.write(data)
        else:
            self.buffer.append(data)

    def end(self):
        self.conn.close()

class Response(object):
    def __init__(self, request):
        self.request = request
        self.time=time.time()
        self.stream = None
        self.buffer = []

        def on_session(client, session):
            self.stream = session.stream()
            self.stream.on('data', self.on_data)
            self.stream.on('close', self.on_close)
            for b in self.buffer:
                self.write(b)
        client.session(on_session)

    def on_data(self, s, data):
        self.request.write(data)

    def on_close(self, s):
        self.request.end()

    def write(self,data):
        if self.stream:
            self.stream.write(data)
        else:
            self.buffer.append(data)

    def end(self):
        if self.stream:
            self.stream.close()

class UdpRequest(object):
    def __init__(self, request, protocol):
        self.request = request
        self.protocol = protocol
        self.server = sevent.udp.Server()
        self.server.on("data", self.on_data)

        self.local_addr = ''
        self.local_port = 0
        self.data_len = 0

    def bind(self):
        self.server = sevent.udp.Server()
        port = random.randint(2048, 65534)
        self.server.bind(('0.0.0.0', port))
        return '0.0.0.0', port

    def on_data(self, s, address, buffer):
        data = buffer.next()
        while data:
            self.local_addr, self.local_port, data = self.protocol.unpack_udp(data)
            data = "".join([struct.pack(">H",len(self.protocol.remote_addr)),self.protocol.remote_addr,struct.pack('>H',self.protocol.remote_port), data])
            self.request.response.write(struct.pack(">I",len(data)) + data)
            data = buffer.next()

    def write_data(self, address, port, data):
        self.server.write((self.local_addr, self.local_port), self.protocol.pack_udp(address, port, data))

    def write(self, data):
        if self.data_len == 0:
            self.data_len, = struct.unpack(">I", data.read(4))
        if len(data) >= self.data_len:
            address_len, = struct.pack(">H", data.read(2))
            address = data.read(address_len)
            port = struct.pack(">H", data.read(2))
            self.write_data(address, port, data.read(self.data_len - address_len - 4))
            self.data_len = 0

    def close(self):
        self.server.close()
        self.server = None

class Request(object):
    _requests=[]
    def __init__(self, conn):
        self.stage = 0
        self.inet_ut = '\x01'
        self.conn = conn
        self.response = None
        self.protocol=None
        self.protocol_parse_end=False
        self.time=time.time()
        self.udp_request = None

        conn.on('data', self.on_data)
        conn.on('end', self.on_end)
        conn.on('close', self.on_close)

    def parse(self,data):
        try:
            self.protocol.parse(data)
        except ProtocolParseEndError,e:
            self.protocol_parse_end=True
            self.inet_ut = e.inet_ut
            if e.inet_ut == '\x01' and self.protocol.remote_addr.strip() == '0.0.0.0' and not self.protocol.remote_port:
                raise Exception("adder is empty %:%", self.protocol.remote_addr, self.protocol.remote_port)

            rule = Rule(self.protocol.remote_addr)
            if config.USE_RULE and not rule.check():
                by_pass = "direct"
                self.response = PassResponse(self)
                self.response.write(e.data)
            else:
                by_pass = "proxy"
                self.response=Response(self)
                self.response.write("".join([e.inet_ut, struct.pack(">H",len(self.protocol.remote_addr)),self.protocol.remote_addr,struct.pack('>H',self.protocol.remote_port),e.data]))
            logging.info('connecting by %s %s:%s %s',by_pass, self.protocol.remote_addr,self.protocol.remote_port,len(self._requests))
        except:
            logging.error(traceback.format_exc())
            self.end()

    def start_udp_server(self):
        self.udp_request = UdpRequest(self, self.protocol)
        return self.udp_request.bind()

    def on_data(self, s, data):
        if self.protocol is None:
            data = data.read(-1)
            if data[0] == '\x05':
                self.protocol = Sock5Protocol(self)
            else:
                self.protocol = HttpProtocol(self)
            self.parse(data)
        elif not self.protocol_parse_end:
            data = data if isinstance(data, basestring) else data.read(-1)
            self.parse(data)
        else:
            self.response.write(data)

    def on_end(self, s):
       pass

    def on_close(self, s):
        if self.response:
            self.response.end()
        if self.udp_request:
            self.udp_request.close()
        self._requests.remove(self)
        logging.info('connected %s:%s %s %.3fs %s/%s',self.protocol.remote_addr if self.protocol else '',
                     self.protocol.remote_port if self.protocol else '',
                     len(self._requests),time.time()-self.time,
                     format_data_count(self.response.stream._send_data_len if self.response and self.response.stream else 0),
                     format_data_count(self.response.stream._recv_data_len if self.response and self.response.stream else 0))
        self.response = None

    def write(self,data):
        if self.inet_ut == '\x01':
            self.conn.write(data)
        else:
            self.udp_request.write(data)

    def end(self):
        self.conn.end()

    @classmethod
    def on_connection(cls, s, conn):
        Request._requests.append(cls(conn))
        
    @classmethod
    def on_session_close(cls, session):
        for request in list(Request._requests):
            request.end()

    @classmethod
    def on_session(cls, client, session):
        server.on('connection', Request.on_connection)
        redirect_server.on('connection', RedirectRequest.on_connection)
        ss_server.on('connection', SSRequest.on_connection)
        session.on('close', Request.on_session_close)

class RedirectRequest(Request):
    def on_data(self, s, data):
        if self.protocol is None:
            data = data.read(-1)
            self.protocol = RedirectProtocol(self)
            self.parse(data)
        elif not self.protocol_parse_end:
            data = data if isinstance(data, basestring) else data.read(-1)
            self.parse(data)
        else:
            self.response.write(data)

class SSRequest(Request):
    def on_data(self, s, data):
        if self.protocol is None:
            data = data.read(-1)
            self.protocol = SSProtocol(self)
            self.parse(data)
        elif not self.protocol_parse_end:
            data = data if isinstance(data, basestring) else data.read(-1)
            self.parse(data)
        else:
            data = data if isinstance(data, basestring) else data.read(-1)
            data = self.protocol._crypto.decrypt(data)
            self.response.write(data)

    def write(self,data):
        data = data if isinstance(data, basestring) else data.read(-1)
        data = self.protocol._crypto.encrypt(data)
        self.conn.write(data)

if __name__ == '__main__':
    logging.info('shadowsocks v2.0')
    try:
        logging.info("starting server at port %d ..." % config.PORT)
        loop = sevent.instance()
        client=Client(config.SERVER, config.REMOTE_PORT, 4, config.KEY, config.METHOD.replace("-", "_"))
        server = sevent.tcp.Server()
        redirect_server = sevent.tcp.Server()
        ss_server = sevent.tcp.Server()

        client.on('session', Request.on_session)

        server.listen((config.BIND_ADDR, config.PORT))
        redirect_server.listen((config.BIND_ADDR, config.PORT + 1))
        ss_server.listen((config.BIND_ADDR, config.PORT + 2))
        client.open()
        loop.start()
    except:
        import traceback
        traceback.print_exc()
