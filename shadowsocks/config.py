# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import os
import json
import sys
import getopt
import logging

optlist, args = getopt.getopt(sys.argv[1:], 'c:s:p:k:b:l:m:v')
config_file = dict(optlist)['-c'] if '-c' in dict(optlist) else 'config.json'

def load_conf():
    with open(config_file, 'rb') as f:
        return json.load(f)

def parse_hosts(exclude_ips=None):
    etc_path = '/etc/hosts'
    if 'WINDIR' in os.environ:
        etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
    hosts = []
    try:
        with open(etc_path, 'r', encoding="utf-8") as f:
            for line in f.readlines():
                line = line.strip()
                if not line or line[0] == '#':
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                if exclude_ips and parts[0] in exclude_ips:
                    continue
                for i in range(1, len(parts)):
                    hostname = parts[i].strip()
                    if hostname and hostname not in ("ip6-localhost", "localhost"):
                        hosts.append(hostname)
        return hosts
    except IOError:
        return hosts

config = load_conf()
SERVER = config.get('server', "127.0.0.1")
REMOTE_PORT = config.get('server_port', 443)
BIND_ADDR = config.get("bind_addr", "0.0.0.0")
PORT = config.get('local_port', 1099)
SSPORT = config.get("sslocal_port", PORT+1)
KEY = config.get('password', '')
METHOD = config.get('method', None)
SESSION_ID = config.get("session_id", 0)
TIME_OUT = config.get("time_out", 60)
LOG_LEVEL = logging.INFO
MAX_CONNECTIONS = int(config.get("max_connections", 10))
USE_RULE = bool(config.get("use_rule", False))
LOCAL_NETWORK = str(config.get("local_network", ''))
LOCAL_HOSTS = set(config.get("local_hosts", []))
PROXY_ADDR = config.get("proxy_addr")
PROXY_PORT = config.get("proxy_port", 443)
SSKEY = config.get("sspassword", KEY)
SSMETHOD = config.get("ssmethod", METHOD)
SSPROXYS = set(config.get("ssproxys", []))
EDNS_CLIENT_SUBNETS = config.get("edns_client_subnets", {
    "8.8.8.8": "119.29.29.29"
})
VIRTUAL_PROXY_ADDR = config.get("virtual_proxy_addr")
DOMAIN_HOSTS = config.get("domain_hosts", {})

for key, value in optlist:
    if key == '-p':
        REMOTE_PORT = int(value)
    elif key == '-k':
        KEY = value
    elif KEY == '-b':
        BIND_ADDR = value
    elif key == '-l':
        PORT = int(value)
    elif key == '-s':
        SERVER = value
    elif key == '-m':
        METHOD = value
    elif key == '-v':
        LOG_LEVEL = logging.NOTSET

if not LOCAL_HOSTS:
    LOCAL_HOSTS = set(parse_hosts([VIRTUAL_PROXY_ADDR] if VIRTUAL_PROXY_ADDR else None))

def config_domain_hosts():
    if not DOMAIN_HOSTS:
        return
    import sevent
    for domain, ip in DOMAIN_HOSTS.items():
        sevent.DNSResolver.default()._hosts[domain] = ip

def reload():
    global SERVER, REMOTE_PORT, BIND_ADDR, PORT, SSPORT, KEY, METHOD, SESSION_ID, TIME_OUT,\
        LOG_LEVEL, MAX_CONNECTIONS, USE_RULE, LOCAL_NETWORK, LOCAL_HOSTS, PROXY_ADDR, PROXY_PORT,\
        SSKEY, SSMETHOD, SSPROXYS, EDNS_CLIENT_SUBNETS, VIRTUAL_PROXY_ADDR, DOMAIN_HOSTS

    config = load_conf()
    SERVER = config.get('server', "127.0.0.1")
    REMOTE_PORT = config.get('server_port', 443)
    BIND_ADDR = config.get("bind_addr", "0.0.0.0")
    PORT = config.get('local_port', 1099)
    SSPORT = config.get("sslocal_port", PORT + 1)
    KEY = config.get('password', '')
    METHOD = config.get('method', None)
    SESSION_ID = config.get("session_id", 0)
    TIME_OUT = config.get("time_out", 60)
    LOG_LEVEL = logging.INFO
    MAX_CONNECTIONS = int(config.get("max_connections", 10))
    USE_RULE = bool(config.get("use_rule", False))
    LOCAL_NETWORK = str(config.get("local_network", ''))
    LOCAL_HOSTS = set(config.get("local_hosts", []))
    PROXY_ADDR = config.get("proxy_addr")
    PROXY_PORT = config.get("proxy_port", 443)
    SSKEY = config.get("sspassword", KEY)
    SSMETHOD = config.get("ssmethod", METHOD)
    SSPROXYS = set(config.get("ssproxys", []))
    EDNS_CLIENT_SUBNETS = config.get("edns_client_subnets", {
        "8.8.8.8": "119.29.29.29"
    })
    VIRTUAL_PROXY_ADDR = config.get("virtual_proxy_addr")
    DOMAIN_HOSTS = config.get("domain_hosts", {})

    if not LOCAL_HOSTS:
        LOCAL_HOSTS = set(parse_hosts([VIRTUAL_PROXY_ADDR] if VIRTUAL_PROXY_ADDR else None))

logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)1.1s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
