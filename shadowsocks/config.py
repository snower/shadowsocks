# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import json
import sys
import getopt
import logging

optlist, args = getopt.getopt(sys.argv[1:], 'c:s:p:k:b:l:m:v')
config_file=dict(optlist)['-c'] if '-c' in dict(optlist) else 'config.json'
with open(config_file, 'rb') as f:
    config = json.load(f)
SERVER = config['server']
REMOTE_PORT = config['server_port']
BIND_ADDR=config.get("bind_addr","0.0.0.0")
PORT = config['local_port']
KEY = config['password']
METHOD = config.get('method', None)
TIME_OUT=config.get("time_out",60)
LOG_LEVEL = logging.INFO
MAX_CONNECTIONS = int(config.get("max_connections", 10))
USE_RULE = bool(config.get("use_rule", True))

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