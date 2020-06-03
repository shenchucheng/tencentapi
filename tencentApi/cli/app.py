#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# File Name: tencent-cns.py
# Author: Shechucheng
# Created Time: 2020-05-29 00:26:39

import os
import pickle
import logging
import json
from socket import AF_INET
from fire import Fire
from tencentApi.cns import get_host_ip, DDns, ip_check, get_addr_ip


def ip(ipv4=False):
    """
    返回本机联网ip地址
    不指定ipv4时，默认返回ipv6地址
    :param ipv4: bool default=False
    """
    
    if ipv4:
        ip = get_host_ip(AF_INET, '119.29.29.29')
    else:
        ip = get_host_ip()
    return ip
    

def config():
    """本机网络环境测试"""
    logging.basicConfig(level=10, format='%(message)s')
    ip_check()


def profile(filename=''):
    """
    创建profile模板文件
    :param filename: 指定模板存储位置, 不指定时返回模板字符串
    """
    doc = {
        "secretId"  : "",
        "secretKey" : "",
        "domain"    : "",
        "record"    : {
            "name"  : "",
            "type"  : "AAAA"
        },
        "create"    : {
            "subDomain" : "",
            "type"  : "AAAA"
            },
        "log"       : {
            "level" : 10
        }

    }
    if filename:
        with open(filename, 'w') as f:
            json.dump(doc, f)
    else:
        return json.dumps(doc)



class ddns(DDns):
    """
    动态域名解析 
    """ 
    def __init__(self, profile='', debug='', domain='', record='', secretId='', secretKey='', **kwargs):
        if profile:
            with open(profile, 'r') as f:
                config = json.load(f)
            config.update(kwargs)
        else:
            config = kwargs

        kwargs = {
                'domain'    : domain,
                'secretId'  : secretId,
                'secretKey' : secretKey,
            }
        for k, v in kwargs.items():
            config[k] = v or config.get(k, '')

        log = config.pop('log', {})
        logging.basicConfig(**log)

        super().__init__(**config)

def main():
    Fire({
        "ip": ip,
        "config": config,
        "profile": profile,
        "resolve": get_addr_ip,
        "ddns": ddns 
        })
    

if __name__ == "__main__":
    main()

