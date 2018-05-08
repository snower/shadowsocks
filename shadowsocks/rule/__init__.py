# -*- coding: utf-8 -*-
#14-6-6
# create by: snower

from default import rules, load_rule


class Rule(object):
    def __init__(self, host):
        self.host = host

    def check(self):
        load_rule()

        if self.host in rules:
            return True

        hosts = self.host.split(".")
        if len(rules) > 2:
            for i in range(len(rules) - 2):
                host = ".".join(hosts[-(i+2):])
                if  host in rules:
                    return True
        return False