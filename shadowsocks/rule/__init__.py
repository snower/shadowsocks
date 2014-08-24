# -*- coding: utf-8 -*-
#14-6-6
# create by: snower

from default import rules


class Rule(object):
    def __init__(self, host):
        self.host = host

    def check(self):
        hosts = self.host.split(".")
        for i in range(len(rules)):
            host = ".".join(hosts[-(i+2):])
            if  host in rules[i]:
                return True
        return False