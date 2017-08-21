# -*- coding: utf-8 -*-
# 2014/8/24
# create by: snower

import json

rules = {
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