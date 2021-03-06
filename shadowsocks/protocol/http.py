# -*- coding: utf-8 -*-
#14-6-3
# create by: snower

from protocol import Protocol, ProtocolParseEndError

class HttpProtocol(Protocol):
    def __init__(self, *args, **kwargs):
        super(HttpProtocol, self).__init__(*args, **kwargs)

        self.method=None

    def get_method(self, data):
        index = data.find(b" ")
        self.method = data[:index]
        return data[index+1:]

    def parse_addr(self, addr_info):
        index = addr_info.find(b" ")
        if index > 0:
            addr_info = addr_info[:index]
        addr_info = addr_info.split(b":")
        self.remote_addr = addr_info[0].decode("utf-8")
        if len(addr_info) == 2:
            self.remote_port = int(addr_info[1])
        else:
            self.remote_port = 80
        if not self.remote_addr or not self.remote_port:
            raise Exception(addr_info)

    def parse_http(self, data):
        data = data[7:]
        index = data.find(b"/")
        self.parse_addr(data[:index])
        raise ProtocolParseEndError(b"".join([self.method, b' ', data[index:]]))

    def parse_https(self, data):
        index = data.find(b" ")
        self.parse_addr(data[:index])
        self.request.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        raise ProtocolParseEndError(b'')

    def parse(self,data):
        if self.method is None:
            data=self.get_method(data)
        if self.method.lower() == b"connect":
            self.parse_https(data)
        elif self.method.lower() in (b"get", b"post", b"put", b"options", b"head", b"delete", b"patch"):
            self.parse_http(data)
        else:
            raise Exception("unknown method %s" % self.method)

