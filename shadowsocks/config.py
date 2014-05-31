# -*- coding: utf-8 -*-
#14-4-22
# create by: snower

import json
import sys
import getopt
import logging

with open('config.json', 'rb') as f:
    config = json.load(f)
SERVER = config['server']
REMOTE_PORT = config['server_port']
BIND_ADDR=config.get("bind_addr","0.0.0.0")
PORT = config['local_port']
KEY = config['password']
METHOD = config.get('method', None)
TIME_OUT=config.get("time_out",60)

argv = sys.argv[1:]

level = logging.INFO

optlist, args = getopt.getopt(argv, 's:p:k:b:l:m:v')
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
        level = logging.NOTSET

logging.basicConfig(level=level, format='%(asctime)s %(levelname)1.1s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')