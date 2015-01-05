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
import socket
import encrypt
from utils import *
from protocol import ProtocolParseEndError
from protocol.http import HttpProtocol
from protocol.sock5 import Sock5Protocol
from xstream.client import Client
from rule import Rule
import config

class PassResponse(object):
    def __init__(self, request):
        self.conn = sevent.tcp.Socket()
        self.request = request
        self.is_connected=False
        self.buffer=[]
        self.time=time.time()*1000
        self.data_count=0

        self.conn.on('connect', self.on_connect)
        self.conn.on('data', self.on_data)
        self.conn.on('close', self.on_close)
        self.conn.on('end', self.on_end)
        self.conn.connect((self.request.protocol.remote_addr,self.request.protocol.remote_port),30)

    def on_connect(self, s):
        self.is_connected=True
        if self.buffer:
            self.write("".join(self.buffer))

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
            self.data_count+=len(data)
        else:
            self.buffer.append(data)

    def end(self):
        self.conn.close()

class Response(object):
    def __init__(self, request):
        self.request = request
        self.encryptor = encrypt.Encryptor(config.KEY, config.METHOD)
        self.time=time.time()
        self.data_count=0
        self.stream = None
        self.buffer = []

        def on_session(client, session):
            self.stream = session.stream()
            self.stream.on('data', self.on_data)
            self.stream.on('close', self.on_close)
            if self.buffer:
                self.write("".join(self.buffer))
        client.session(on_session)

    def on_data(self, s, data):
        data = self.encryptor.decrypt(data)
        self.request.write(data)

    def on_close(self, s):
        self.request.end()

    def write(self,data):
        if self.stream:
            self.stream.write(self.encryptor.encrypt(data))
            self.data_count += len(data)
        else:
            self.buffer.append(data)

    def end(self):
        if self.stream:
            self.stream.close()

class Request(object):
    _requests=[]
    def __init__(self, conn):
        self.stage = 0
        self.conn = conn
        self.response = None
        self.protocol=None
        self.protocol_parse_end=False
        self.time=time.time()*1000
        self.data_count=0
        self.udp_server = None

        conn.on('data', self.on_data)
        conn.on('end', self.on_end)
        conn.on('close', self.on_close)

    def parse(self,data):
        try:
            self.protocol.parse(data)
        except ProtocolParseEndError,e:
            self.protocol_parse_end=True
            rule = Rule(self.protocol.remote_addr)
            if config.USE_RULE and not rule.check():
                by_pass = "direct"
                if self.protocol.remote_addr.strip() and self.protocol.remote_port > 0:
                    self.response = PassResponse(self)
                    self.response.write(e.data)
                else:
                    self.end()
            else:
                by_pass = "proxy"
                if self.protocol.remote_addr.strip() and self.protocol.remote_port > 0:
                    self.response=Response(self)
                    self.response.write("".join([e.inet_ut, struct.pack(">H",len(self.protocol.remote_addr)),self.protocol.remote_addr,struct.pack('>H',self.protocol.remote_port),e.data]))
                else:
                    self.end()
            logging.info('connecting by %s %s:%s %s',by_pass, self.protocol.remote_addr,self.protocol.remote_port,len(self._requests))
        except:
            logging.error(sys.exc_info())
            self.end()

    def start_udp_server(self):
        self.udp_server = sevent.udp.Server()
        port = random.randint(2048, 65534)
        self.udp_server.bind(('0.0.0.0', port))
        self.udp_server.on("data", self.on_udp_data)
        return port

    def on_data(self, s, data):
        if self.protocol is None:
            if data[0]=='\x05':
                self.protocol=Sock5Protocol(self)
            else:
                self.protocol=HttpProtocol(self)
        if not self.protocol_parse_end:
            self.parse(data)
        else:
            self.response.write(data)

    def on_udp_data(self, s, address, data):
        addr, port, data = self.protocol.parse_udp_addr_info(data)
        self.response.write("".join(['\x02', struct.pack(">H",len(self.protocol.remote_addr)),self.protocol.remote_addr,struct.pack('>H',self.protocol.remote_port), struct.pack(">H",len(data)), data]))

    def on_end(self, s):
       pass

    def on_close(self, s):
        if self.udp_server:
            self.udp_server.close()
        if self.response:
            self.response.end()
        self._requests.remove(self)
        logging.info('connected %s:%s %s %sms %s/%s',self.protocol.remote_addr if self.protocol else '', self.protocol.remote_port if self.protocol else '',len(self._requests),time.time()*1000-self.time,format_data_count(self.response.data_count if self.response else 0),format_data_count(self.data_count))

    def write(self,data):
        if not self.udp_server:
            self.conn.write(data)
            self.data_count+=len(data)
        else:
            self.udp_server.w

    def end(self):
        self.conn.close()

    @staticmethod
    def on_connection(s, conn):
        Request._requests.append(Request(conn))

    @staticmethod
    def  on_session(client, session):
        server.on('connection', Request.on_connection)

if __name__ == '__main__':
    logging.info('shadowsocks v2.0')
    encrypt.init_table(config.KEY, config.METHOD)
    try:
        logging.info("starting server at port %d ..." % config.PORT)
        loop = sevent.instance()
        client=Client(config.SERVER, config.REMOTE_PORT, 4, config.KEY, config.METHOD.replace("-", "_"))
        server = sevent.tcp.Server()

        client.on('session', Request.on_session)

        server.listen((config.BIND_ADDR, config.PORT))
        client.open()
        loop.start()
    except:
        import traceback
        traceback.print_exc()
