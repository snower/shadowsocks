# -*- coding: utf-8 -*-
#14-6-6
# create by: snower

import struct
import socket
from . import default

def check_host(host):
    if host in default.rules:
        return True

    hosts = host.split(".")
    for i in range(len(hosts)):
        host = ".".join(hosts[-(i+1):])
        if host in default.rules:
            return True
    return False

def check_ip(ip):
    try:
        ip = struct.unpack(">I", socket.inet_aton(ip))[0]
        for mask in default.masks:
            network = ip >> (32 - mask)
            if network not in default.networks[mask]:
                return False
            if default.networks[mask][network]:
                return True
    except:
        return False
    return False

def reload_rule():
    default.load_rule()
    default.load_networks()