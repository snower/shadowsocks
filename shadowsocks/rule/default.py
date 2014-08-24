# -*- coding: utf-8 -*-
# 2014/8/24
# create by: snower

rules = [
    {
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

        "wikipedia.org",
        "twitter.com",
        "twimg.com",
        "t.co",
        "v2ex.com",
        "facebook.com",
        "akamaihd.net",
        "fbcdn.net",

        "nodejs.org",
        "php.net",
        "jetbrains.com",
        "mongodb.org",
        "github.com",
        "githubusercontent.com",
        "githubapp.com",
        "gravatar.com",
        "bitbucket.org",
        "python.org",
        "readthedocs.org",
        "tornadoweb.org",
        "cython.org",
        "chandlerproject.org",

        "digitalocean.com",
        "amazonaws.com",
        "cloudflare.com",

        "shadowsocks.com",

        "k22.su",
        "avbaidu.net",
        "axshare.com",
        "btbook.net",
        "sstatic.net",
        "chrome.com",
        "eztv.it",
        "ggpht.com",
        "imgur.com",
        "imageab.com",
        "instagram.com",
        "newsmth.net",
        "postimage.org",
        "postimg.org",
        "pypa.io",
        "s8bbs.com",
        "feedsportal.com",
        "goo.gl",
        "tumblr.com",
        "wikimedia.org",
    },
    {
        "google.com.hk",
    }
]

try:
    from rules import rules as user_rules
    for i in range(len(user_rules)):
        if len(rules) > i:
            rules[i] = rules[i] | user_rules[i]
        else:
            rules.append(user_rules[i])
except:
    pass