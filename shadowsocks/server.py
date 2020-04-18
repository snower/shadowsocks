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
import os
os.chdir(os.path.dirname(__file__) or '.')
from collections import deque, defaultdict
import time
import struct
import logging
import sevent
from xstream.server import Server
from utils import format_data_count
import config

class DnsSocket(sevent.udp.Socket):
    _cache = defaultdict(deque)
    _idle_check_timeout = None

    def __init__(self, host_key, *args, **kwargs):
        super(DnsSocket, self).__init__(*args, **kwargs)
        super(DnsSocket, self).on_data(self.on_socket_data)
        super(DnsSocket, self).on_close(self.on_socket_colse)

        self.host_key = host_key
        self.idle_time = 0

    def on_data(self, callback):
        self._events['data'] = {callback}
        self.emit_data = callback

    def on_socket_data(self, socket, buffer):
        pass

    def on_socket_colse(self, socket):
        try:
            self.__class__._cache[self.host_key].remove(socket)
        except Exception as e:
            if self.idle_time <= 0:
                logging.error("dns socket close error %s %s", self, e)

    def close(self):
        self.on_data(self.on_socket_data)
        self.idle_time = time.time()
        self._cache[self.host_key].append(self)

    def do_close(self):
        super(DnsSocket, self).close()

    @classmethod
    def instance(cls, host_key):
        if not cls._idle_check_timeout:
            cls._idle_check_timeout = loop.add_timeout(120, cls.check_timeout)
        host_cache = cls._cache[host_key]
        while host_cache:
            socket = host_cache.pop()
            if socket._state == sevent.udp.STATE_CLOSED:
                continue
            socket.idle_time = 0
            return socket
        return DnsSocket(host_key)

    @classmethod
    def check_timeout(cls):
        try:
            now = time.time()
            for key, host_cache in cls._cache.items():
                while host_cache:
                    socket = host_cache[0]
                    if socket.idle_time and now - socket.idle_time >= 15 * 60:
                        host_cache.popleft()
                        try:
                            socket.do_close()
                        except Exception as e:
                            logging.error("dns socket close error %s %s", socket, e)
                        continue
                    elif socket._state == sevent.udp.STATE_CLOSED:
                        host_cache.popleft()
                        continue
                    break
        finally:
            cls._idle_check_timeout = loop.add_timeout(120, cls.check_timeout)

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
        except Exception as e:
            logging.error("parse addr error: %s %s", e, data)
            return  None, ''

    def on_data(self, s, buffer):
        while buffer:
            data, address = buffer.next()
            data = "".join([struct.pack(">H", len(address[0])), address[0], struct.pack(">H", address[1]), data])
            self.request.write(data)

    def write(self, buffer):
        data = buffer.next()
        while data:
            address, data = self.parse_addr_info(data)
            if address:
                if self.conn is None:
                    if address[1] == 53:
                        self.conn = DnsSocket.instance(address[0])
                    else:
                        self.conn = sevent.udp.Socket()
                    self.conn.on("data", self.on_data)
                self.conn.write((data, address))
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
            self.proxy_connection.enable_nodelay()
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
            try:
                self.proxy_connection.write(data)
            except sevent.errors.SocketClosed:
                pass
        else:
            self.buffer.append(str(data))
        self.send_data_len += len(data)

    def end(self):
        self.proxy_connection.end()

class FileBuffer(object):
    cache_path = None

    def __init__(self):
        self.filename = None
        self.rlen = 0
        self.wlen = 0
        self.fp = None

    def open(self):
        cache_path = self.init_dir()
        self.filename = cache_path + os.path.sep + struct.pack("!Q", int(id(self))).encode("hex")
        self.fp = open(self.filename, 'wb+')

    def init_dir(self):
        if self.cache_path:
            return self.cache_path

        cache_path = os.environ.get("CACHE_PATH")
        if cache_path:
            self.__class__.cache_path = os.path.abspath(cache_path)
        else:
            self.__class__.cache_path = os.path.abspath("./cache")
        if not os.path.exists(self.__class__.cache_path):
            os.mkdir(self.__class__.cache_path)
        return self.__class__.cache_path

    def write(self, data):
        self.fp.seek(0, os.SEEK_END)
        self.fp.write(data)
        self.wlen += len(data)

    def read(self, size = -1):
        if self.rlen >= self.wlen:
            return ''

        self.fp.seek(self.rlen, os.SEEK_SET)
        if size < 0:
            size = self.wlen - self.rlen
        else:
            size = min(size, self.wlen - self.rlen)
        self.rlen += size
        return self.fp.read(size)

    def close(self):
        self.fp.close()
        try:
            os.remove(self.filename)
        except:
            logging.info("remove filename error: %s", self.filename)

class Response(object):
    def __init__(self, request):
        self.conn = sevent.tcp.Socket()
        self.request = request
        self.is_connected = False
        self.is_ended = False
        self.buffer = None
        self.file_buffer = None
        self.time=time.time()

        if self.request.remote_port == 53:
            self.conn.enable_fast_open()
        self.conn.enable_nodelay()

        self.conn.on('connect', self.on_connect)
        self.conn.on('data', self.on_data)
        self.conn.on('close', self.on_close)
        self.conn.on('end', self.on_end)
        self.conn.connect((self.request.remote_addr, self.request.remote_port),30)

    def on_connect(self, s):
        self.is_connected = True
        self.request.wbuffer.on("drain", self.on_drain)
        self.request.wbuffer.on("regain", self.on_regain)

        if self.buffer:
            self.write(self.buffer)

    def on_drain(self, buffer):
        if self.file_buffer is False or self.file_buffer:
            return

        self.file_buffer = FileBuffer()
        try:
            self.file_buffer.open()
        except Exception as e:
            logging.error("open filebuffer error: %s", e)
            self.file_buffer = False

    def on_regain(self, buffer):
        if self.file_buffer.wlen > self.file_buffer.rlen:
            wlen = self.request.wbuffer._drain_size - len(self.request.wbuffer) + 16
            self.request.write(self.file_buffer.read(wlen))

        if self.file_buffer.wlen <= self.file_buffer.rlen and self.is_ended:
            self.request.end()

    def on_data(self, s, data):
        if not self.file_buffer:
            return self.request.write(data)

        if self.request.wbuffer.full:
            return self.file_buffer.write(data.read())

        if self.file_buffer.wlen > self.file_buffer.rlen:
            self.file_buffer.write(data.read())
            wlen = self.request.wbuffer._drain_size - len(self.request.wbuffer) + 16
            return self.request.write(self.file_buffer.read(wlen))
        return self.request.write(data)

    def on_end(self, s):
        pass

    def on_close(self, s):
        if not self.file_buffer:
            return self.request.end()
        self.is_ended = True

    def write(self, data):
        if not data:
            return

        if self.is_connected or self.conn.is_enable_fast_open:
            try:
                self.conn.write(data)
            except sevent.errors.SocketClosed:
                pass
        else:
            self.buffer = data

    def end(self):
        self.conn.end()
        if self.file_buffer:
            self.file_buffer.close()
            self.file_buffer = None

class Request(object):
    _requests=[]
    def __init__(self, stream):
        self.stream=stream
        self.remote_addr = ''
        self.remote_port = 0
        self.header_length=0
        self.response = None
        self.time=time.time()
        self.rbuffer, self.wbuffer = stream.buffer

        self.stream.on('data', self.on_data)
        self.stream.on('close', self.on_close)

    def parse_addr_info(self,data):
        try:
            addr_len, = struct.unpack('>H',data.read(2))
            self.remote_addr = data.read(addr_len)
            self.remote_port, = struct.unpack('>H', data.read(2))
            self.header_length = addr_len + 4
        except Exception as e:
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
