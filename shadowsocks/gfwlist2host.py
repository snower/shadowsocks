# -*- coding: utf-8 -*-
#14-6-6
# create by: snower

import json

fp = open("gfwlist.txt")

rules = set([])

def parse(line):
    if line[0] == '/':
        return ''
    if line[:7] == "http://":
        line = line[7:]
    elif line[:7] == "https://":
        line = line[7:]

    try:
        index = line.index("/")
        line = line[:index]
    except:
        pass

    if line[0] == ".":
        line = line[1:]
    return line

for line in fp:
    if "AutoProxy" in line:
        continue

    line = line.strip()
    if not line or line[0] == '!':
        continue

    if line[:2] == "||":
        line = parse(line[2:])
        if line:
            rules.add(line)
    elif line[0] == "|":
        line = parse(line[1:])
        if line:
            rules.add(line)
    elif line[0] == "@":
        continue
    else:
        line = parse(line)
        if line:
            rules.add(line)

fp.close()

with open("gfwlist_rule.json", "w") as fp:
    json.dump(list(rules), fp)