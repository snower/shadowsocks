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
import time
import struct
import logging
import socket
import sevent
from xstream.server import Server
from utils import *
import config

class UdpResponse(object):
    def __init__(self, request):
        self.request = request
        self.conn = sevent.udp.Socket()
        self.conn.on("data", self.on_data)

        self.data_len = 0
        self.time=time.time()

    def parse_addr_info(self, data):
        try:
            addr_len, = struct.unpack('>H', data[:2])
            remote_addr = data[2: addr_len + 2]
            remote_port, = struct.unpack('>H', data[addr_len + 2: addr_len + 4])
            return (remote_addr, remote_port), data[addr_len + 4:]
        except Exception, e:
            logging.error("parse addr error: %s %s", e, data)
            return  None, ''

    def on_data(self, s, address, buffer):
        data = buffer.next()
        while data:
            data = "".join([struct.pack(">H", len(address[0])), address[0], struct.pack(">H", address[1]), data])
            self.request.write(data)
            data = buffer.next()

    def write(self, buffer):
        data = buffer.next()
        while data:
            address, data = self.parse_addr_info(data)
            if address:
                self.conn.write(address, data)
            data = buffer.next()

    def end(self):
        self.conn.close()
        self.conn = None

class ProxyResponse(object):
    def __init__(self, connection):
        self.connection = connection
        self.is_connected = False
        self.buffer = []
        self.time = time.time()
        self.send_data_len = 0
        self.recv_data_len = 0

        if config.PROXY_ADDR:
            self.proxy_connection = sevent.tcp.Socket()
            self.proxy_connection.enable_fast_open()
            self.proxy_connection.on('connect', self.on_connect)
            self.proxy_connection.on('data', self.on_data)
            self.proxy_connection.on('close', self.on_close)
            self.proxy_connection.on('end', self.on_end)
            self.proxy_connection.connect((config.PROXY_ADDR, config.PROXY_PORT), 30)
        else:
            self.proxy_connection = None

    def on_connect(self, s):
        self.is_connected = True
        if self.buffer:
            self.write("".join(self.buffer))

    def on_data(self, s, data):
        self.connection.write(data)
        self.recv_data_len += len(data)

    def on_close(self, s):
        self.connection.end()

    def on_end(self, s):
        pass

    def write(self, data):
        if not self.connection:
            return

        if not data or not self.proxy_connection:
            self.connection.close()
            return

        if self.is_connected or self.proxy_connection.is_enable_fast_open:
            self.proxy_connection.write(data)
        else:
            self.buffer.append(str(data))
        self.send_data_len += len(data)

    def end(self):
        self.proxy_connection.end()

class Response(object):
    def __init__(self, request):
        self.conn = sevent.tcp.Socket()
        self.request = request
        self.is_connected=False
        self.buffer= None
        self.time=time.time()
        self.conn.enable_fast_open()

        self.conn.on('connect', self.on_connect)
        self.conn.on('data', self.on_data)
        self.conn.on('close', self.on_close)
        self.conn.on('end', self.on_end)
        self.conn.connect((self.request.remote_addr,self.request.remote_port),30)

    def on_connect(self, s):
        self.is_connected=True
        if self.buffer:
            self.write(self.buffer)

    def on_data(self, s, data):
        self.request.write(data)

    def on_close(self, s):
        self.request.end()

    def on_end(self, s):
        pass

    def write(self,data):
        if not data:
            return
        if self.is_connected or self.conn.is_enable_fast_open:
            self.conn.write(data)
        else:
            self.buffer = data

    def end(self):
        self.conn.end()

class Request(object):
    _requests=[]
    def __init__(self, stream):
        self.stream=stream
        self.remote_addr = ''
        self.remote_port = 0
        self.header_length=0
        self.response = None
        self.time=time.time()

        self.stream.on('data', self.on_data)
        self.stream.on('close', self.on_close)

    def parse_addr_info(self,data):
        try:
            addr_len, = struct.unpack('>H',data.read(2))
            self.remote_addr = data.read(addr_len)
            self.remote_port, = struct.unpack('>H', data.read(2))
            self.header_length = addr_len + 4
        except Exception,e:
            logging.error("parse addr error: %s %s",e,data)
            self.end()
            return False
        if self.remote_addr == '0.0.0.0' or not self.remote_port:
            logging.error("parse addr error: %s %s %s",data,self.remote_addr,self.remote_port)
            self.end()
            return False
        return True

    def on_data(self, s, data):
        if self.response is None:
            if self.stream.capped:
                self.response = UdpResponse(self)
                logging.info('udp connecting %s', self.stream)
            else:
                if self.parse_addr_info(data):
                    logging.info('connecting %s:%s %s',self.remote_addr, self.remote_port, len(self._requests))
                    self.response = Response(self)
            if data:
                self.response.write(data)
        else:
            self.response.write(data)

    def on_close(self, s):
        if self.response:
            self.response.end()
        self._requests.remove(self)
        if isinstance(self.response, Response):
            logging.info('connected %s:%s %s %.3fs %s/%s',self.remote_addr, self.remote_port,len(self._requests),
                         time.time()-self.time,
                         format_data_count(self.stream._send_data_len),
                         format_data_count(self.stream._recv_data_len))
        else:
            logging.info('udp connected %s', self.stream)
        self.response = None

    def write(self, data):
        self.stream.write(data)

    def end(self):
        self.stream.close()

    @staticmethod
    def on_stream(session, stream):
        Request._requests.append(Request(stream))
        
    @staticmethod
    def on_session_close(session):
        for request in list(Request._requests):
            request.end()

    @staticmethod
    def on_session(server, session):
        session.on("stream",Request.on_stream)
        session.on("close",Request.on_session_close)

    @staticmethod
    def on_connection(server, connection, data):
        p = ProxyResponse(connection)
        def on_close(connection):
            logging.info("server %s proxy connection %s close %s %s %s %s", server, connection, config.PROXY_ADDR, config.PROXY_PORT,
                         format_data_count(p.send_data_len), format_data_count(p.recv_data_len))
        connection.on("close", on_close)
        p.write(data)
        logging.info("server %s proxy connection %s to %s %s", server, connection, config.PROXY_ADDR, config.PROXY_PORT)

if __name__ == '__main__':
    logging.info('shadowsocks v2.0')
    try:
        logging.info("starting server at port %d ..." % config.PORT)
        loop = sevent.instance()
        server = Server(config.PORT, config.BIND_ADDR, config.KEY, config.METHOD.replace("-", "_"))
        server.on('session', Request.on_session)
        server.on("connection", Request.on_connection)
        server.start()
        loop.start()
    except:
        import traceback
        traceback.print_exc()
