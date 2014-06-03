# -*- coding: utf-8 -*-
#14-6-3
# create by: snower

from protocol import Protocol,ProtocolParseEndError

class HttpProtocol(Protocol):
    def parse(self,data):
        index=data.find("http://")
        method=data[:index]
        data=data[index+7:]
        index=data.find("/")
        self.remote_addr=data[:index]
        self.remote_port=80
        raise ProtocolParseEndError(method+data[index:])
