# -*- coding: utf-8 -*-
#14-4-26
# create by: snower

import socket

def format_data_count(count):
    if count < 1024:
        return "%dB" % count
    elif count < 1024*1024:
        return "%.3fK" % (count/1024.0)
    elif count < 1024*1024*1024:
        return "%.3fM" % (count/(1024.0*1024.0))
    elif count < 1024*1024*1024*1024:
        return "%.3fG" % (count/(1024.0*1024.0*1024.0))
    elif count < 1024*1024*1024*1024*1024:
        return "%.3fT" % (count/(1024.0*1024.0*1024.0*1024.0))
    return "%dB" % count

def is_ip(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
        return socket.AF_INET
    except (TypeError, ValueError, OSError, IOError):
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return socket.AF_INET6
        except (TypeError, ValueError, OSError, IOError):
            return False