# -*- coding: utf-8 -*-
#14-6-3
# create by: snower

class ProtocolParseEndError(Exception):
    def __init__(self,data,*args,**kwargs):
        super(ProtocolParseEndError,self).__init__(*args,**kwargs)
        self.data=data

class Protocol(object):
    def __init__(self,request):
        self.request=request
        self.remote_addr=''
        self.remote_port=0

    def parse(self,data):
        raise ProtocolParseEndError('')