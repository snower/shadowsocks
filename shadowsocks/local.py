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
import dnslib
from utils import *
from protocol import ProtocolParseEndError
from protocol.http import HttpProtocol
from protocol.sock4 import Sock4Protocol
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

class DnsResponse(object):
    def __init__(self, request, address, remote_addr, remote_port):
        self.request = request
        self.address = address
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.time = time.time()
        self.stream = None
        self.buffer = []
        self.conn = sevent.udp.Socket()
        self.conn.on("data", self.on_udp_data)

        def on_session(client, session):
            self.stream = session.stream(priority=1, capped=True)
            self.stream.on('data', self.on_data)
            self.stream.on('close', self.on_close)
            for b in self.buffer:
                self.write(b)

        client.session(on_session)

    def on_udp_data(self, s, address, buffer):
        data = buffer.next()
        while data:
            self.request.write(self.address, data)
            data = buffer.next()

    def on_data(self, s, data):
        self.request.write(self.address, data)

    def on_close(self, s):
        self.request.end(self.address)

    def write(self, data):
        try:
            dns_record = dnslib.DNSRecord.parse(data)
            if dns_record.questions:
                host = str(dns_record.questions[0].qname)
                if host[-1] == ".":
                    host = host[:-1]
                rule = Rule(host)
                if not rule.check():
                    self.conn.write(("114.114.114.114", 53), data)
                    logging.info("direct nsloop %s", str(dns_record.questions[0].qname))
                    return
        except Exception as e:
            logging.info("parse dns error:%s", e)

        data = "".join([struct.pack(">H", len(self.remote_addr)), self.remote_addr, struct.pack('>H', self.remote_port), data])
        if self.stream:
            self.stream.write(data)
        else:
            self.buffer.append(data)

    def end(self):
        if self.stream:
            self.stream.close()
        if self.conn:
            self.conn.close()

class UdpResponse(object):
    def __init__(self, request, address, remote_addr, remote_port):
        self.request = request
        self.address = address
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.time=time.time()
        self.stream = None
        self.buffer = []

        def on_session(client, session):
            self.stream = session.stream(priority = 1, capped = True)
            self.stream.on('data', self.on_data)
            self.stream.on('close', self.on_close)
            for b in self.buffer:
                self.write(b)
        client.session(on_session)

    def on_data(self, s, data):
        self.request.write(self.address, data)

    def on_close(self, s):
        self.request.end(self.address)

    def write(self,data):
        data = "".join([struct.pack(">H", len(self.remote_addr)), self.remote_addr, struct.pack('>H', self.remote_port), data])
        if self.stream:
            self.stream.write(data)
        else:
            self.buffer.append(data)

    def end(self):
        if self.stream:
            self.stream.close()

class UdpRequest(object):
    caches= {}

    def __init__(self, server, protocol):
        self.protocol = protocol
        self.server = server
        self.server.on("data", self.on_data)

    def on_data(self, s, address, buffer):
        data = buffer.next()
        while data:
            remote_addr, remote_port, data = self.protocol.unpack_udp(data)
            if address not in self.caches:
                if remote_port == 53:
                    response = self.caches[address] = DnsResponse(self, address, remote_addr, remote_port)
                else:
                    response = self.caches[address] = UdpResponse(self, address, remote_addr, remote_port)
                logging.info('%s udp connecting %s %s %s', self.protocol, address, remote_addr, remote_port)
            else:
                response = self.caches[address]
            response.write(data)
            data = buffer.next()

    def parse_addr_info(self, data):
        try:
            addr_len, = struct.unpack('>H', data[:2])
            remote_addr = data[2: addr_len + 2]
            remote_port, = struct.unpack('>H', data[addr_len + 2: addr_len + 4])
            return (remote_addr, remote_port), data[addr_len + 4:]
        except Exception, e:
            logging.error("parse addr error: %s %s", e, data)
            return None, ''

    def write(self, address, buffer):
        data = buffer.next()
        while data:
            remote_address, data = self.parse_addr_info(data)
            if address:
                data = self.protocol.pack_udp(remote_address[0], remote_address[1], data)
                self.server.write(address, data)
            data = buffer.next()

    def end(self, address):
        try:
            del self.caches[address]
            logging.info('%s udp connected %s', self.protocol, address)
        except:
            pass

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

class Request(object):
    _requests=[]
    def __init__(self, conn):
        self.conn = conn
        self.response = None
        self.protocol=None
        self.protocol_parse_end=False
        self.time=time.time()

        conn.on('data', self.on_data)
        conn.on('end', self.on_end)
        conn.on('close', self.on_close)

    def parse(self,data):
        try:
            self.protocol.parse(data)
        except ProtocolParseEndError,e:
            self.protocol_parse_end = True
            if e.inet_ut != '\x01':
                return

            if self.protocol.remote_addr.strip() == '0.0.0.0' and not self.protocol.remote_port:
                raise Exception("adder is empty %:%", self.protocol.remote_addr, self.protocol.remote_port)


            if config.USE_RULE:
                rule = Rule(self.protocol.remote_addr)
                if  not rule.check():
                    self.response = PassResponse(self)
                    self.response.write(e.data)
                    logging.info('%s connecting by direct %s:%s %s',self.protocol, self.protocol.remote_addr,self.protocol.remote_port,len(self._requests))
                    return

            self.response=Response(self)
            self.response.write("".join([struct.pack(">H",len(self.protocol.remote_addr)),self.protocol.remote_addr,struct.pack('>H',self.protocol.remote_port),e.data]))
            logging.info('%s connecting by proxy %s:%s %s',self.protocol, self.protocol.remote_addr,self.protocol.remote_port,len(self._requests))
        except:
            logging.error(traceback.format_exc())
            self.end()

    def on_data(self, s, data):
        if self.protocol is None:
            data = data.read(-1)
            if data[0] == '\x05':
                self.protocol = Sock5Protocol(self)
            elif data[0] == '\x04':
                self.protocol = Sock4Protocol(self)
            else:
                http_data = data[:10]
                index = http_data.find(' ')
                if index > 0 and (http_data[:index].lower() == "connect" or http_data[index+1:index+5] == "http"):
                    self.protocol = HttpProtocol(self)
                else:
                    self.protocol = RedirectProtocol(self)
            self.parse(data)
        elif not self.protocol_parse_end:
            self.parse(data.read(-1))
        else:
            self.response.write(data)

    def on_end(self, s):
       pass

    def on_close(self, s):
        if self.response:
            self.response.end()
        self._requests.remove(self)
        logging.info('%s connected %s:%s %s %.3fs %s/%s', self.protocol, self.protocol.remote_addr if self.protocol else '',
                     self.protocol.remote_port if self.protocol else '',
                     len(self._requests),time.time()-self.time,
                     format_data_count(self.response.stream._send_data_len if self.response and self.response.stream else 0),
                     format_data_count(self.response.stream._recv_data_len if self.response and self.response.stream else 0))
        self.response = None

    def write(self,data):
        self.conn.write(data)

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
        ss_server.on('connection', SSRequest.on_connection)
        session.on('close', Request.on_session_close)

class SSRequest(Request):
    def on_data(self, s, data):
        if self.protocol is None:
            data = data.read(-1)
            self.protocol = SSProtocol(self)
            self.parse(data)
        elif not self.protocol_parse_end:
            self.parse(data.read(-1))
        else:
            data = self.protocol._crypto.decrypt(data.read(-1))
            self.response.write(data)

    def write(self,data):
        data = self.protocol._crypto.encrypt(data.read(-1))
        self.conn.write(data)

if __name__ == '__main__':
    logging.info('shadowsocks v2.0')
    try:
        logging.info("starting server at port %d ..." % config.PORT)
        loop = sevent.instance()
        client=Client(config.SERVER, config.REMOTE_PORT, 3, config.KEY, config.METHOD.replace("-", "_"))
        server = sevent.tcp.Server()
        ss_server = sevent.tcp.Server()

        udp_server = sevent.udp.Server()
        ss_udp_server = sevent.udp.Server()

        udp_request = UdpRequest(udp_server, Sock5Protocol(None))
        ss_udp_request = UdpRequest(ss_udp_server, SSProtocol(None))

        client.on('session', Request.on_session)

        server.listen((config.BIND_ADDR, config.PORT))
        ss_server.listen((config.BIND_ADDR, config.SSPORT))

        udp_server.bind((config.BIND_ADDR, config.PORT))
        ss_udp_server.bind((config.BIND_ADDR, config.SSPORT))

        client.open()
        loop.start()
    except:
        import traceback
        traceback.print_exc()
