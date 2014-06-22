# -*- coding: utf-8 -*-
#14-6-3
# create by: snower

from protocol import Protocol,ProtocolParseEndError

class HttpProtocol(Protocol):
    def __init__(self,*args,**kwargs):
        super(HttpProtocol,self).__init__(*args,**kwargs)

        self.method=None

    def get_method(self,data):
        index=data.find(" ")
        self.method=data[:index]
        return data[index+1:]

    def parse_addr(self,addr_info):
        addr_info=addr_info.split(":")
        self.remote_addr=addr_info[0]
        if len(addr_info)==2:
            self.remote_port=int(addr_info[1])
        else:
            self.remote_port=80
        if not self.remote_addr or not self.remote_port:
            raise Exception(addr_info)

    def parse_http(self,data):
        data=data[7:]
        index=data.find("/")
        self.parse_addr(data[:index])
        raise ProtocolParseEndError("".join([self.method,' ',data[index:]]))

    def parse_https(self,data):
        index=data.find(" ")
        self.parse_addr(data[:index])
        self.request.write("HTTP/1.1 200 Connection Established\r\n\r\n")
        raise ProtocolParseEndError('')

    def parse(self,data):
        if self.method is None:
            data=self.get_method(data)
        if self.method.lower()=="connect":
            self.parse_https(data)
        else:
            self.parse_http(data)

