# -*- coding: utf-8 -*-
# 2014/8/24
# create by: snower

import struct
from collections import defaultdict
import socket
import json

default_rules = {
    "google.com",
    "youtube.com",
    "ytimg.com",
    "googlevideo.com",
    "googlesyndication.com",
    "googleusercontent.com",
    "doubleclick.net",
    "googletagservices.com",
    "google-analytics.com",
    "gstatic.com",
}

rules = set([])
networks = defaultdict(dict)
masks = []

def load_rule():
    rules.clear()
    rules.update(default_rules)
    try:
        with open("gfwlist_rule.json") as fp:
            gfwlist_rules = json.load(fp)
            for rule in gfwlist_rules:
                rules.add(rule)
    except:
        pass

    try:
        with open("user_rule.json") as fp:
            user_rules = json.load(fp)
            for rule in user_rules:
                rules.add(rule)
    except:
        pass

def load_networks():
    global networks, masks
    networks, masks = defaultdict(dict), []
    try:
        try:
            with open("china_ip_list.txt") as fp:
                for line in fp:
                    info = line.strip().split("/")
                    mask = int(info[1]) if len(info) >= 2 else 32
                    network = struct.unpack(">I", socket.inet_aton(info[0]))[0] >> (32 - mask)
                    networks[mask][network] = True
        except:
            pass

        for line in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            info = line.strip().split("/")
            mask = int(info[1]) if len(info) >= 2 else 32
            network = struct.unpack(">I", socket.inet_aton(info[0]))[0] >> (32 - mask)
            networks[mask][network] = True

        masks = sorted(networks.keys())
        for i in range(len(masks)):
            for j in range(i + 1, len(masks)):
                for network in networks[masks[j]]:
                    network = network >> (masks[j] - masks[i])
                    if network in networks[masks[i]]:
                        continue
                    networks[masks[i]][network] = False
    except:
        pass

load_rule()
load_networks()