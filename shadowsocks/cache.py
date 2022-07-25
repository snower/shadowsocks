# -*- coding: utf-8 -*-
# 2021/5/14
# create by: snower

import os
import time
from collections import defaultdict, deque
import logging
import sevent

class FileBuffer(object):
    cache_path = None

    def __init__(self):
        self.filename = None
        self.rlen = 0
        self.wlen = 0
        self.fp = None

    def open(self):
        cache_path = self.init_dir()
        self.filename = cache_path + os.path.sep + str(id(self))
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

    def read(self, size=-1):
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
        buffer.read()

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

    def end(self):
        self.close()

    def do_close(self):
        super(DnsSocket, self).close()

    @classmethod
    def instance(cls, host_key):
        if not cls._idle_check_timeout:
            cls._idle_check_timeout = sevent.current().add_timeout(30, cls.check_timeout)
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
            for key, host_cache in tuple(cls._cache.items()):
                while host_cache:
                    socket = host_cache[0]
                    if socket.idle_time and now - socket.idle_time >= 5 * 60:
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
            cls._idle_check_timeout = sevent.current().add_timeout(30, cls.check_timeout)