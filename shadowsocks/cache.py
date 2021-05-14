# -*- coding: utf-8 -*-
# 2021/5/14
# create by: snower

import os
import struct
import logging

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