# -*- coding: utf-8 -*-
#14-4-26
# create by: snower

def format_data_count(count):
    if count<1024:
        return "%dB" % count
    elif count<1024*1024:
        return "%.3fK" % (count/1024.0)
    elif count<1024*1024*1024:
        return "%.3fM" % (count/(1024.0*1024.0))