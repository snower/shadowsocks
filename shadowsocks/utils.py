# -*- coding: utf-8 -*-
#14-4-26
# create by: snower

def format_data_count(count):
    if count<1024:
        return "%sB" % count
    elif count<1024*1024:
        return "%sK" % (count/1024)
    elif count<1024*1024*1024:
        return "%sM" % (count/(1024*1024))