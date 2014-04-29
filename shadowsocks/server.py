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
import encrypt
import ssloop
from xstream.session import BaseSession,Server
from utils import *
import config

class Response(object):
    def __init__(self, request):
        self.conn = ssloop.Socket(BaseSession._loop)
        self.request = request
        self.is_connected=False
        self.buffer=[]
        self.time=time.time()*1000
        self.data_count=0

        self.conn.on('connect', self.on_connect)
        self.conn.on('data', self.on_data)
        self.conn.on('close', self.on_close)
        self.conn.on('end', self.on_end)
        self.conn.connect((self.request.remote_addr,self.request.remote_port))

    def on_connect(self, s):
        self.is_connected=True
        if self.buffer:self.write("".join(self.buffer))

    def on_data(self, s, data):
        self.request.write(data)

    def on_close(self, s):
        pass

    def on_end(self, s):
        self.request.end()

    def write(self,data):
        if self.is_connected:
            self.conn.write(data)
            self.data_count+=len(data)
        else:
            self.buffer.append(data)

    def end(self):
        self.conn.close()

class Request(object):
    _requests=[]
    def __init__(self, stream):
        self.stream=stream
        self.stage = 0
        self.remote_addr = ''
        self.remote_port = 0
        self.header_length=0
        self.response = None
        self.encryptor = encrypt.Encryptor(config.KEY, config.METHOD)
        self.time=time.time()*1000
        self.data_count=0

        self.stream.on('data', self.on_data)
        self.stream.on('close', self.on_close)

    def parse_addr_info(self,data):
        addr_type = ord(data[0])
        if addr_type == 1:
            self.remote_addr = socket.inet_ntoa(data[1:5])
            self.remote_port = data[5:7]
            self.header_length = 7
        elif addr_type == 4:
            self.remote_addr = socket.inet_ntop(data[1:17])
            self.remote_port = data[17:19]
            self.header_length = 19
        elif addr_type == 3:
            addr_len = ord(data[1])
            self.remote_addr = data[2:2 + addr_len]
            self.remote_port = data[2 + addr_len:2 + addr_len + 2]
            self.header_length = 2 + addr_len + 2
        else:
            raise Exception(data)
        self.remote_port = struct.unpack('>H', self.remote_port)[0]
        if not self.remote_addr or not self.remote_port:
            raise Exception(data)

    def on_data(self, s, data):
        data = self.encryptor.decrypt(data)
        if self.stage == 0:
            try:
                self.parse_addr_info(data)
            except:
                logging.error(sys.exc_info())
                self.end()
                return

            logging.info('connecting %s:%s %s',self.remote_addr,self.remote_port,len(self._requests))
            self.response = Response(self)
            self.response.write(data[self.header_length:])
            self.stage = 5
        elif self.stage == 5:
            self.response.write(data)

    def on_close(self, s):
        if self.response:
            self.response.end()
        self._requests.remove(self)
        logging.info('connected %s:%s %s %sms %s/%s',self.remote_addr, self.remote_port,len(self._requests),time.time()*1000-self.time,format_data_count(self.data_count),format_data_count(self.response.data_count if self.response else 0))

    def write(self,data):
        data = self.encryptor.encrypt(data)
        self.stream.write(data)
        self.data_count+=len(data)

    def end(self):
        self.stream.close()

    @staticmethod
    def on_stream(session, stream):
        Request._requests.append(Request(stream))

    @staticmethod
    def on_session(server,session):
        session.on("stream",Request.on_stream)

if __name__ == '__main__':
    logging.info('shadowsocks v2.0')
    encrypt.init_table(config.KEY, config.METHOD)
    try:
        logging.info("starting server at port %d ..." % config.PORT)
        server = Server('0.0.0.0',config.PORT)
        server.on('session', Request.on_session)
        server.listen()
    except KeyboardInterrupt:
        sys.exit(0)
