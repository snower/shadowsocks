# -*- coding: utf-8 -*-
#14-6-6
# create by: snower

import struct
import socket
from . import default

def has_host_rule():
    return default.rules

def check_host(host):
    if host in default.rules:
        return True

    hosts = host.split(".")
    for i in range(len(hosts)):
        host = ".".join(hosts[-(i+1):])
        if host in default.rules:
            return True
    return False

def has_ip_rule():
    return default.masks

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

def has_ip6_rule():
    return default.mask6s

def check_ip6(ip):
    try:
        ip = struct.unpack(">Q", socket.inet_pton(socket.AF_INET6, ip)[:8])[0]
        for mask in default.mask6s:
            network = ip >> (64 - mask)
            if network not in default.network6s[mask]:
                return False
            if default.network6s[mask][network]:
                return True
    except:
        return False
    return False

def reload_rule():
    default.load_rule()
    default.load_networks()
    default.load_network6s()