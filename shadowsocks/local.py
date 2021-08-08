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

import os
os.chdir(os.path.dirname(__file__) or '.')

import time
import struct
import signal
import traceback
import sevent
import logging
import socket
import dnslib
from xstream.client import Client
from protocol import ProtocolParseEndError
from protocol.http import HttpProtocol
from protocol.sock4 import Sock4Protocol
from protocol.sock5 import Sock5Protocol
from protocol.redirect import RedirectProtocol
from protocol.ss import SSProtocol
from rule import check_host, check_ip, check_ip6, reload_rule, has_host_rule, has_ip_rule, has_ip6_rule
from utils import format_data_count
from cache import FileBuffer, DnsSocket
import config

class PassResponse(object):
    def __init__(self, request, protocol, remote_addr, remote_port):
        self.request = request
        self.protocol = protocol
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.is_connected = False
        self.buffer = None
        self.time = time.time()
        self.send_data_len = 0
        self.recv_data_len = 0

        self.conn = sevent.tcp.Socket()
        self.conn.enable_fast_open()
        self.conn.enable_nodelay()
        self.conn.on('connect', self.on_connect)
        self.conn.on('data', self.on_data)
        self.conn.on('close', self.on_close)
        self.conn.on('end', self.on_end)
        self.conn.connect((self.request.protocol.remote_addr, self.request.protocol.remote_port), 30)

    def on_connect(self, s):
        self.is_connected = True
        rbuffer, wbuffer = self.conn.buffer
        wbuffer.link(self.request.rbuffer)
        self.request.wbuffer.link(rbuffer)
        if self.buffer:
            self.write(self.buffer)

    def on_data(self, s, data):
        self.recv_data_len += len(data)
        self.request.write(data)

    def on_close(self, s):
        self.request.end()

    def on_end(self, s):
        pass

    def write(self, data):
        self.send_data_len += len(data)
        if self.is_connected or self.conn.is_enable_fast_open:
            try:
                self.conn.write(data)
            except sevent.errors.SocketClosed:
                pass
        else:
            self.buffer = data

    def end(self):
        self.conn.end()

    def get_send_data_len(self):
        return self.send_data_len

    def get_recv_data_len(self):
        return self.recv_data_len

class UdpPassResponse(object):
    def __init__(self, request, address, remote_addr, remote_port, proxy_address):
        self.request = request
        self.address = address
        self.proxy_address = proxy_address
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.time = time.time()
        self.data_time = time.time()
        self.conn = None
        self.send_data_len = 0
        self.recv_data_len = 0

    def on_close(self, s):
        if self.conn:
            self.request.end(self.address)
        self.conn = None

    def on_data(self, s, buffer):
        while buffer:
            data, address = buffer.next()
            self.request.write(self.address, address, data)
            self.recv_data_len += len(data)
        self.data_time = time.time()

    def write(self, data):
        if not data:
            return
        if not self.conn:
            self.conn = sevent.udp.Socket()
            if self.remote_addr and self.remote_addr == "255.255.255.255":
                self.conn.enable_broadcast()
            self.conn.on("data", self.on_data)
            self.conn.on("close", self.on_close)

        try:
            self.conn.write((data, (self.remote_addr, self.remote_port)))
        except sevent.errors.SocketClosed:
            pass
        self.send_data_len += len(data)
        self.data_time = time.time()

    def end(self):
        if self.conn:
            self.conn.end()
            self.conn = None
        self.request.end(self.address)

    def get_send_data_len(self):
        return self.send_data_len

    def get_recv_data_len(self):
        return self.recv_data_len

class DnsResponse(object):
    def __init__(self, request, address, remote_addr, remote_port, proxy_address, is_udp=True):
        self.request = request
        self.address = address
        self.proxy_address = proxy_address
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.proxy_remote_addr = remote_addr
        self.direct_remote_addr = config.EDNS_CLIENT_SUBNETS[remote_addr]
        self.time = time.time()
        self.data_time = time.time()
        self.buffer = []
        self.stream = None
        self.conn = None
        self.is_udp = is_udp
        self.use_udp = False
        self.tcp_rdata = b''
        self.send_data_len = 0
        self.recv_data_len = 0

        loop.add_timeout(3, self.on_timeout)

    def on_session(self, client, session):
        if self.stream:
            return

        if self.is_udp or self.use_udp:
            self.stream = session.stream(priority=1, capped=True)
        else:
            self.stream = session.stream()
        self.stream.on('data', self.on_data)
        self.stream.on('close', self.on_close)
        for b in self.buffer:
            self.write(b)
        self.buffer = []

    def on_timeout(self):
        if time.time() - self.data_time >= 8:
            if self.stream:
                self.stream.close()
            if self.conn:
                self.conn.close()
            if self.is_udp:
                self.request.end(self.address)
            else:
                self.request.end()
            self.stream = None
            self.conn = None
        else:
            loop.add_timeout(3, self.on_timeout)

    def on_udp_data(self, s, buffer):
        self.recv_data_len += len(buffer)
        self.data_time = time.time()
        while buffer:
            data, address = buffer.next()
            if self.is_udp:
                self.request.write(self.address, address, data)
            else:
                self.request.write(struct.pack("!H", len(data)) + data)

    def on_data(self, s, buffer):
        self.recv_data_len += len(buffer)
        self.data_time = time.time()
        if self.is_udp:
            data = buffer.next()
            while data:
                remote_address, data = self.parse_addr_info(data)
                self.request.write(self.address, remote_address, data)
                data = buffer.next()
        else:
            if self.use_udp:
                data = buffer.next()
                while data:
                    remote_address, data = self.parse_addr_info(data)
                    self.request.write(struct.pack("!H", len(data)) + data)
                    data = buffer.next()
            else:
                self.request.write(buffer)

    def on_close(self, s):
        if self.stream:
            self.stream.close()
        if self.conn:
            self.conn.close()
        if self.is_udp:
            self.request.end(self.address)
        else:
            self.request.end()
        self.stream = None
        self.conn = None

    def write_query(self, data):
        host = ''
        dns_record = dnslib.DNSRecord.parse(data)
        if dns_record.questions:
            host = str(dns_record.questions[0].qname)
            if host[-1] == ".":
                host = host[:-1]
            if not check_host(host):
                if self.conn is None:
                    self.conn = DnsSocket.instance(self.direct_remote_addr)
                    self.conn.on_data(self.on_udp_data)
                    self.remote_addr = self.direct_remote_addr
                dns_record = self.handle_edns_client_subnet(dns_record)
                self.conn.write((bytes(dns_record.pack()), (self.direct_remote_addr, 53)))
                logging.info("direct nsloop %s", host)
                return True, host
        return False, host

    def write(self, buffer):
        self.data_time = time.time()
        self.send_data_len += len(buffer)
        if not self.is_udp:
            self.tcp_rdata += buffer.read(-1) if isinstance(buffer, sevent.Buffer) else buffer
                
        while True:
            if self.is_udp:
                if isinstance(buffer, sevent.Buffer):
                    data = buffer.next()
                else:
                    if not buffer:
                        return
                    data, buffer = buffer, None
                if not data:
                    return
            else:
                if len(self.tcp_rdata) < 2:
                    return
                data_len, = struct.unpack("!H", self.tcp_rdata[:2])
                if len(self.tcp_rdata) - 2 < data_len:
                    return

                data, self.tcp_rdata = self.tcp_rdata[2: data_len + 2], self.tcp_rdata[data_len + 2:]

            host = ''
            try:
                succed, host = self.write_query(data)
                if succed:
                    continue
                self.use_udp = True
            except Exception as e:
                logging.info("parse dns error:%s", e)

            if self.stream is None:
                client.session(self.on_session)
            if not self.is_udp and not self.use_udp:
                data = struct.pack("!H", len(data)) + data
            proxy_remote_addr = self.proxy_remote_addr.encode("utf-8")
            data = b"".join([struct.pack(">H", len(proxy_remote_addr)), proxy_remote_addr,
                             struct.pack('>H', self.remote_port), data])
            if self.stream:
                self.stream.write(data)
            else:
                self.buffer.append(data)
            logging.info("proxy nsloop %s", host)

    def end(self):
        if self.stream:
            self.stream.close()
        if self.conn:
            self.conn.end()
        self.stream = None
        self.conn = None

    def parse_addr_info(self, data):
        try:
            addr_len, = struct.unpack('>H', data[:2])
            remote_addr = data[2: addr_len + 2].decode("utf-8")
            remote_port, = struct.unpack('>H', data[addr_len + 2: addr_len + 4])
            return (remote_addr, remote_port), data[addr_len + 4:]
        except Exception as e:
            logging.error("parse addr error: %s %s", e, data)
            return None, ''

    def handle_edns_client_subnet(self, dns_record):
        client_id = self.address[0] if not self.proxy_address else self.proxy_address[0]
        if client_id.startswith(config.LOCAL_NETWORK):
            return dns_record

        opt_rr = None
        for rr in dns_record.ar:
            if rr.rtype == 41:
                opt_rr = rr
                break

        if opt_rr is None:
            try:
                client_subnet = dnslib.EDNSOption(8, struct.pack("!HH4s", 0x0001, 0x2000,
                                                                 socket.inet_aton(client_id)))
            except socket.error:
                client_subnet = dnslib.EDNSOption(8, struct.pack("!HH16s", 0x0002, 0x2000,
                                                                 socket.inet_pton(socket.AF_INET6, client_id)))
            opt_rr = dnslib.RR(dnslib.DNSLabel(None), 41, 4096, 0, [client_subnet])
            dns_record.add_ar(opt_rr)
            logging.info("dns edns_client_subnet %s", client_id)
        else:
            client_subnet = None
            for ednsoption in opt_rr.rdata:
                if ednsoption.code == 8:
                    client_subnet = ednsoption
                    break

            if not client_subnet:
                try:
                    client_subnet = dnslib.EDNSOption(8, struct.pack("!HH4s", 0x0001, 0x2000,
                                                                     socket.inet_aton(client_id)))
                except socket.error:
                    client_subnet = dnslib.EDNSOption(8, struct.pack("!HH16s", 0x0002, 0x2000,
                                                                     socket.inet_pton(socket.AF_INET6, client_id)))
                opt_rr.rdata.append(client_subnet)
                logging.info("dns edns_client_subnet %s", client_id)
        return dns_record

    def get_send_data_len(self):
        return self.send_data_len

    def get_recv_data_len(self):
        return self.recv_data_len

class UdpResponse(object):
    def __init__(self, request, address, remote_addr, remote_port, proxy_address):
        self.request = request
        self.address = address
        self.proxy_address = proxy_address
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.time = time.time()
        self.stream = None
        self.buffer = []

        def on_session(client, session):
            self.stream = session.stream(priority=1, capped = True)
            self.stream.on('data', self.on_data)
            self.stream.on('close', self.on_close)
            for b in self.buffer:
                self.write(b)
        client.session(on_session)

    def on_data(self, s, buffer):
        data = buffer.next()
        while data:
            remote_address, data = self.parse_addr_info(data)
            self.request.write(self.address, remote_address, data)
            data = buffer.next()

    def on_close(self, s):
        if self.stream:
            self.stream.close()
        self.request.end(self.address)
        self.stream = None

    def write(self, data):
        if not data:
            return

        remote_addr = self.remote_addr.encode("utf-8")
        data = b"".join([struct.pack(">H", len(remote_addr)), remote_addr,
                         struct.pack('>H', self.remote_port), data])
        if self.stream:
            self.stream.write(data)
        else:
            self.buffer.append(data)

    def end(self):
        if self.stream:
            self.stream.close()
        self.stream = None
        self.conn = None

    def parse_addr_info(self, data):
        try:
            addr_len, = struct.unpack('>H', data[:2])
            remote_addr = data[2: addr_len + 2].decode("utf-8")
            remote_port, = struct.unpack('>H', data[addr_len + 2: addr_len + 4])
            return (remote_addr, remote_port), data[addr_len + 4:]
        except Exception as e:
            logging.error("parse addr error: %s %s", e, data)
            return None, ''

    def get_send_data_len(self):
        return self.stream._send_data_len if self.stream else 0

    def get_recv_data_len(self):
        return self.stream._recv_data_len if self.stream else 0

class UdpRequest(object):
    caches = {}

    def __init__(self, server, protocol):
        self.protocol = protocol
        self.server = server
        self.server.on("data", self.on_data)

    @classmethod
    def on_data_timeout(cls):
        try:
            now = time.time()
            for address, response in tuple(cls.caches.items()):
                if not isinstance(response, UdpPassResponse):
                    continue

                if now - response.data_time >= 120:
                    response.end()
        finally:
            loop.add_timeout(30, cls.on_data_timeout)

    def on_data(self, s, buffer):
        while buffer:
            data, address = buffer.next()
            remote_type, remote_addr, remote_port, data, proxy_address = self.protocol.unpack_udp(data, address)
            if address not in self.caches:
                if remote_port == 53 and remote_addr in config.EDNS_CLIENT_SUBNETS:
                    response = self.__class__.caches[address] = DnsResponse(self, address, remote_addr, remote_port,
                                                                            proxy_address)
                    response.write(data)
                    logging.info('%s udp connecting by dns %s:%s -> %s:%s %d', self.protocol, proxy_address[0],
                                 proxy_address[1], remote_addr, remote_port, len(self.caches))
                    return

                is_local_host = False
                if remote_addr in config.LOCAL_HOSTS:
                    is_local_host = True
                elif remote_type == 1:
                    if check_ip(remote_addr):
                        is_local_host = True
                    elif remote_port != 443 and not has_ip_rule() and isinstance(self.protocol, SSProtocol):
                        is_local_host = True
                elif remote_type == 4:
                    if check_ip6(remote_addr):
                        is_local_host = True
                    elif remote_port != 443 and not has_ip6_rule() and isinstance(self.protocol, SSProtocol):
                        is_local_host = True
                elif config.USE_RULE:
                    is_local_host = True if not check_host(remote_addr) else False

                if is_local_host:
                    response = self.__class__.caches[address] = UdpPassResponse(self, address, remote_addr, remote_port,
                                                                                proxy_address)
                    response.write(data)
                    logging.info('%s udp connecting by direct %s:%s -> %s:%s %d', self.protocol, proxy_address[0],
                                 proxy_address[1], remote_addr, remote_port, len(self.caches))
                    return

                response = self.__class__.caches[address] = UdpResponse(self, address, remote_addr, remote_port,
                                                                                proxy_address)
                response.write(data)
                logging.info('%s udp connecting by proxy %s:%s -> %s:%s %d', self.protocol, proxy_address[0],
                             proxy_address[1], remote_addr, remote_port, len(self.caches))
                return

            response = self.caches[address]
            response.write(data)

    def write(self, address, remote_address, data):
        if not data:
            return 
        if address:
            data = self.protocol.pack_udp(remote_address[0], remote_address[1], data)
            self.server.write((data, address))

    def end(self, address):
        try:
            response = self.caches[address]
            del self.__class__.caches[address]
            if response.proxy_address:
                address = response.proxy_address
            logging.info('%s udp connected %s:%s -> %s:%s %s %.3fs %s/%s', self.protocol,
                         address[0], address[1],
                         response.remote_addr, response.remote_port,
                         len(self.caches), time.time() - response.time,
                         format_data_count(response.get_send_data_len()),
                         format_data_count(response.get_recv_data_len()))
        except:
            pass

class Response(object):
    def __init__(self, request, protocol, remote_addr, remote_port):
        self.request = request
        self.protocol = protocol
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.time = time.time()
        self.is_ended = False
        self.stream = None
        self.buffer = None
        self.file_buffer = None
        client.session(self.on_session)

    def on_session(self, client, session):
        self.stream = session.stream()
        self.stream.on('data', self.on_data)
        self.stream.on('close', self.on_close)

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

    def on_close(self, s):
        if not self.file_buffer:
            self.request.end()
        self.is_ended = True

    def write(self, data):
        if self.stream:
            self.stream.write(data)
        else:
            self.buffer = data

    def end(self):
        if self.stream:
            self.stream.close()
        if self.file_buffer:
            self.file_buffer.close()
            self.file_buffer = None

    def get_send_data_len(self):
        return self.stream._send_data_len if self.stream else 0

    def get_recv_data_len(self):
        return self.stream._recv_data_len if self.stream else 0

class Request(object):
    _requests = []

    def __init__(self, conn):
        self.conn = conn
        self.address = conn.address
        self.response = None
        self.protocol = None
        self.protocol_parse_end = False
        self.time = time.time()
        self.data_time = time.time()
        self.closed = False
        self.rbuffer, self.wbuffer = conn.buffer

        conn.on('data', self.on_data)
        conn.on('end', self.on_end)
        conn.on('close', self.on_close)

        def on_timeout():
            if self.closed:
                return

            if not self.protocol or not self.protocol_parse_end:
                return self.end()
        loop.add_timeout(15, on_timeout)

    @classmethod
    def on_data_timeout(cls):
        try:
            now = time.time()
            for request in cls._requests:
                if request.closed:
                    continue

                if now - request.data_time > 15 * 60:
                    request.end()
        finally:
            loop.add_timeout(30, cls.on_data_timeout)

    def parse(self, data, buffer):
        try:
            self.protocol.parse(data)
        except ProtocolParseEndError as e:
            self.protocol_parse_end = True
            if e.inet_ut != 1:
                return

            if self.protocol.remote_addr.strip() == '0.0.0.0' and not self.protocol.remote_port:
                raise Exception("adder is empty %:%", self.protocol.remote_addr, self.protocol.remote_port)
                
            if self.protocol.remote_port == 53 and self.protocol.remote_addr in config.EDNS_CLIENT_SUBNETS:
                self.response = DnsResponse(self, self.address, self.protocol.remote_addr,
                                            self.protocol.remote_port, self.address, is_udp=False)
                if e.data:
                    buffer.write(e.data)
                    self.response.write(buffer)
                logging.info('%s connecting by dns %s:%s -> %s:%s %s', self.protocol,
                             self.address[0], self.address[1],
                             self.response.remote_addr, self.response.remote_port,
                             len(self._requests))
                return

            is_local_host = False
            if self.protocol.remote_addr in config.LOCAL_HOSTS:
                is_local_host = True
            elif self.protocol.remote_type == 1:
                is_local_host = True if check_ip(self.protocol.remote_addr) else False
            elif self.protocol.remote_type == 4:
                is_local_host = True if check_ip6(self.protocol.remote_addr) else False
            elif config.USE_RULE:
                is_local_host = True if not check_host(self.protocol.remote_addr) else False

            if is_local_host:
                self.response = PassResponse(self, self.protocol, self.protocol.remote_addr,
                                             self.protocol.remote_port)
                if e.data:
                    buffer.write(e.data)
                    self.response.write(buffer)
                logging.info('%s connecting by direct %s:%s -> %s:%s %s',self.protocol,
                             self.address[0], self.address[1],
                             self.response.remote_addr, self.response.remote_port,
                             len(self._requests))
                return

            self.response = Response(self, self.protocol, self.protocol.remote_addr, self.protocol.remote_port)
            remote_addr = self.protocol.remote_addr.encode("utf-8")
            buffer.write(b"".join([struct.pack(">H", len(remote_addr)), remote_addr,
                                   struct.pack('>H', self.protocol.remote_port), e.data]))
            if e.data:
                self.response.write(buffer)

            logging.info('%s connecting by proxy %s:%s -> %s:%s %s', self.protocol,
                         self.address[0], self.address[1],
                         self.response.remote_addr, self.response.remote_port,
                         len(self._requests))
        except Exception as e:
            logging.error(e)
            self.end()

    def on_data(self, s, buffer):
        self.data_time = time.time()
        if self.protocol_parse_end:
            if not self.response:
                return
            return self.response.write(buffer)

        if self.protocol is None:
            data = buffer.read(-1)
            if data[0] == 5:
                self.protocol = Sock5Protocol(self)
            elif data[0] == 4:
                self.protocol = Sock4Protocol(self)
            else:
                http_data = data[:10]
                index = http_data.find(b' ')
                if index > 0 and (http_data[:index].lower() == b"connect" or http_data[index+1:index+5] == b"http"):
                    self.protocol = HttpProtocol(self)
                else:
                    self.protocol = RedirectProtocol(self)
            self.parse(data, buffer)
        else:
            self.parse(buffer.read(-1), buffer)

    def on_end(self, s):
       pass

    def on_close(self, s):
        self.closed = True
        if self.response:
            self.response.end()
        self.__class__._requests.remove(self)
        logging.info('%s connected %s:%s -> %s:%s %s %.3fs %s/%s', self.protocol,
                     self.address[0], self.address[1],
                     self.response.remote_addr if self.response else (self.protocol.remote_addr if self.protocol else ''),
                     self.response.remote_port if self.response else (self.protocol.remote_port if self.protocol else ''),
                     len(self._requests), time.time()-self.time,
                     format_data_count(self.response.get_send_data_len() if self.response else 0),
                     format_data_count(self.response.get_recv_data_len() if self.response else 0))
        self.response = None
        self.protocol = None

    def write(self, data):
        if self.protocol_parse_end:
            if not self.response:
                return
        self.data_time = time.time()
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
    def __init__(self, conn):
        super(SSRequest, self).__init__(conn)

        self.fastrbuffer = sevent.Buffer()
        self.fastwbuffer = sevent.Buffer()

        self.fastrbuffer.link(self.rbuffer)
        self.rbuffer = self.fastrbuffer

    def on_data(self, s, buffer):
        self.data_time = time.time()
        if self.protocol_parse_end:
            while buffer:
                self.rbuffer.write(self.protocol._crypto.decrypt(buffer.next()))
            self.response.write(self.rbuffer)
            return

        if self.protocol is None:
            self.protocol = SSProtocol(self, self.address)
            self.parse(buffer.read(-1), self.rbuffer)
        else:
            self.parse(buffer.read(-1), self.rbuffer)

    def write(self, data):
        if self.protocol_parse_end:
            if not self.response:
                return

        if data.__class__ == sevent.Buffer:
            while data:
                self.fastwbuffer.write(self.protocol._crypto.encrypt(data.next()))
        else:
            self.fastwbuffer.write(self.protocol._crypto.encrypt(data))
        self.conn.write(self.fastwbuffer)
        self.data_time = time.time()

if __name__ == '__main__':
    def reload():
        config.reload()
        reload_rule()
        sevent.DNSResolver.default().close()
        sevent.DNSResolver._instance = sevent.DNSResolver()
        logging.info("reload finish")
    signal.signal(signal.SIGHUP, lambda signum, frame: sevent.current().add_async(reload))
    signal.signal(signal.SIGINT, lambda signum, frame: sevent.current().stop())
    signal.signal(signal.SIGTERM, lambda signum, frame: sevent.current().stop())

    logging.info('shadowsocks v2.0')
    try:
        logging.info("starting server at port %d ..." % config.PORT)
        reload_rule()
        loop = sevent.instance()
        client = Client(config.SERVER, config.REMOTE_PORT, 3, config.KEY,
                        config.METHOD.replace("-", "_"), config.SESSION_ID)
        server = sevent.tcp.Server()
        ss_server = sevent.tcp.Server()

        server.enable_reuseaddr()
        server.enable_fast_open()
        server.enable_nodelay()
        ss_server.enable_reuseaddr()
        ss_server.enable_fast_open()
        ss_server.enable_nodelay()

        udp_server = sevent.udp.Server()
        ss_udp_server = sevent.udp.Server()

        udp_request = UdpRequest(udp_server, Sock5Protocol(None))
        ss_udp_request = UdpRequest(ss_udp_server, SSProtocol(None, None))

        client.on('session', Request.on_session)

        server.listen((config.BIND_ADDR, config.PORT))
        ss_server.listen((config.BIND_ADDR, config.SSPORT))

        udp_server.bind((config.BIND_ADDR, config.PORT))
        ss_udp_server.bind((config.BIND_ADDR, config.SSPORT))

        client.open()
        loop.add_timeout(30, Request.on_data_timeout)
        loop.add_timeout(30, UdpRequest.on_data_timeout)
        loop.start()
    except:
        traceback.print_exc()
