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

default_networds = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
)

default_netword6s = (
    "fe80::/10",
    "fc00::/7"
)

rules = set([])
networks = defaultdict(dict)
masks = []
network6s = defaultdict(dict)
mask6s = []

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
                    if "#" in line or not line.strip():
                        continue
                    info = line.strip().split("/")
                    mask = int(info[1]) if len(info) >= 2 else 32
                    try:
                        network = struct.unpack(">I", socket.inet_aton(info[0]))[0] >> (32 - mask)
                    except:
                        continue
                    networks[mask][network] = True
        except:
            pass

        for line in default_networds:
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


def load_network6s():
    global network6s, mask6s
    network6s, mask6s = defaultdict(dict), []
    try:
        try:
            with open("china_ip6_list.txt") as fp:
                for line in fp:
                    if "#" in line or not line.strip():
                        continue
                    info = line.strip().split("/")
                    mask = int(info[1]) if len(info) >= 2 else 64
                    try:
                        network = struct.unpack(">Q", socket.inet_pton(socket.AF_INET6, info[0])[:8])[0] >> (64 - mask)
                    except:
                        continue
                    network6s[mask][network] = True
        except:
            pass

        for line in default_networds:
            info = line.strip().split("/")
            mask = int(info[1]) if len(info) >= 2 else 64
            network = struct.unpack(">Q", socket.inet_pton(socket.AF_INET6, info[0])[:8])[0] >> (64 - mask)
            network6s[mask][network] = True

        mask6s = sorted(network6s.keys())
        for i in range(len(mask6s)):
            for j in range(i + 1, len(mask6s)):
                for network in network6s[mask6s[j]]:
                    network = network >> (mask6s[j] - mask6s[i])
                    if network in network6s[mask6s[i]]:
                        continue
                    network6s[mask6s[i]][network] = False
    except:
        pass

load_rule()
load_networks()
load_network6s()