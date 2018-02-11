# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

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
LOCAL_NETWORK = bool(config.get("local_network", ''))
PROXY_ADDR = config.get("proxy_addr")
PROXY_PORT = config.get("proxy_port", 443)

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

logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)1.1s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
