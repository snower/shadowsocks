# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import os
import json
import sys
import getopt
import logging

optlist, args = getopt.getopt(sys.argv[1:], 'c:s:p:k:b:l:m:v')
config_file=dict(optlist)['-c'] if '-c' in dict(optlist) else 'config.json'
try:
    with open(config_file, 'rb') as f:
        config = json.load(f)
except:
    config = {}

def parse_hosts():
    etc_path = '/etc/hosts'
    if 'WINDIR' in os.environ:
        etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
    hosts = []
    try:
        with open(etc_path, 'rb') as f:
            for line in f.readlines():
                line = line.strip()
                if not line or line[0] == '#':
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                for i in range(1, len(parts)):
                    hostname = parts[i].strip()
                    if hostname and hostname not in ("ip6-localhost", "localhost"):
                        hosts.append(hostname)
        return hosts
    except IOError:
        return hosts

SERVER = config.get('server', "127.0.0.1")
REMOTE_PORT = config.get('server_port', 443)
BIND_ADDR=config.get("bind_addr","0.0.0.0")
PORT = config.get('local_port', 1099)
SSPORT = config.get("sslocal_port", PORT+1)
KEY = config.get('password', '')
METHOD = config.get('method', None)
TIME_OUT=config.get("time_out",60)
LOG_LEVEL = logging.INFO
MAX_CONNECTIONS = int(config.get("max_connections", 10))
USE_RULE = bool(config.get("use_rule", False))
LOCAL_NETWORK = str(config.get("local_network", ''))
LOCAL_HOSTS = set(config.get("local_hosts", []))
PROXY_ADDR = config.get("proxy_addr")
PROXY_PORT = config.get("proxy_port", 443)
SSKEY = config.get("sspassword", KEY)
SSMETHOD = config.get("ssmethod", METHOD)
EDNS_CLIENT_SUBNETS = config.get("edns_client_subnets", {
    "8.8.8.8": "119.29.29.29"
})

for key, value in optlist:
    if key == '-p':
        REMOTE_PORT = int(value)
    elif key == '-k':
        KEY = value
    elif KEY=='-b':
        BIND_ADDR=value
    elif key == '-l':
        PORT = int(value)
    elif key == '-s':
        SERVER = value
    elif key == '-m':
        METHOD = value
    elif key == '-v':
        LOG_LEVEL = logging.NOTSET

if not LOCAL_HOSTS:
    LOCAL_HOSTS = set(parse_hosts())

logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)1.1s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
