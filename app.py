#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# File Name: tencent-cns.py
# Author: Shechucheng
# Created Time: 2020-05-29 00:26:39

from logging import basicConfig
from socket import AF_INET
from fire import Fire
from tencentApi.cns import get_host_ip, DDns, ip_check


def ip(**kwargs):
    if kwargs.get('ipv4'):
        ip = get_host_ip(AF_INET, '119.29.29.29')
    else:
        ip = get_host_ip()
    return ip
    

def ddns():
    pass


if __name__ == "__main__":
    basicConfig(level=10)
    Fire({
        "config": ip_check,
        "ip": ip,
        "ddns": DDns
        })

