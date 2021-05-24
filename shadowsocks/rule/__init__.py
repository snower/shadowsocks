# -*- coding: utf-8 -*-
#14-6-6
# create by: snower

import struct
import socket
import logging
from .default import rules, load_rule, networks, masks, load_networks

def check_host(host):
    if host in rules:
        return True

    hosts = host.split(".")
    if len(rules) > 2:
        for i in range(len(rules) - 2):
            host = ".".join(hosts[-(i+2):])
            if host in rules:
                return True
    return False

def check_ip(ip):
    try:
        ip = struct.unpack(">I", socket.inet_aton(ip))[0]
        for mask in masks:
            network = ip >> (32 - mask)
            if network not in networks[mask]:
                return False
            if networks[mask][network]:
                return True
    except:
        return False
    return False

def reload_rule():
    load_rule()
    load_networks()
    logging.info("reload rule success %s %s %s", len(rules), len(networks), len(masks))