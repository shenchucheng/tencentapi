#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# File Name: ddns.py
# Author: Shechucheng
# Created Time: 2020-05-21 17:44:40

"""
本地动态获取ip，并与域名解析记录比较，
当本地ip发生变化时，更新解析记录
@class DDns 继承CnsApi并进行拓展
"""

import sys
import socket
from threading import Thread
from socket import getaddrinfo
from logging import getLogger, basicConfig
from time import sleep
from .cns import CnsApi


logger = getLogger('ddns')


def get_host_ip(family=socket.AF_INET6, dns='240e:4c:4008::1', check=True):
    """
    获取本机ip，参数不同决定ipv4还是ipv6
    修改family参数注意修改dns为对应值
    :param family: AddressFamily 可设置为sock.AF_INET
    :param dns: 公共DNS地址，例如腾讯公共DNS：119.29.29.29
    查询本机ip地址
    :return: str ip地址
    """
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        s.connect((dns, 80))
        ip = s.getsockname()[0]
        return ip
    except Exception as e:
        if check:
            logger.warn('Fail to get local ip for {}'.format(e))
            raise e
    finally:
        s.close()


def get_addr_ip(addr, port=80, **kwargs):
    """
    域名解析 
    :param addr: str 查询域名
    :param port: int 域名端口 默认 80
    :param kwargs: getaddrinfo的其他参数
    """
    try:
        r = getaddrinfo(addr, port, **kwargs)
        if r:
            return set(i[4][0] for i in r)
        else:
            logger.warning('无法解析域名 {}:{} '.format(addr, port))
    except Exception as e:
        # 未联网，域名解析未匹配到记录
        logger.warning('{}:{} 域名解析错误 {}'.format(addr, port, e))


class DDns(CnsApi):
    def __init__(self, domain, record={}, interval=-1, create=False, **kwargs):
        """
        动态域名解析
        :param domain: str 解析域名
        :param record:  dict 解析记录查询信息
            value 二级域名 type 解析类型  id 记录id ***参考record的keys
        :param interval: int 动态解析时间间隔 默认为解析记录的ttl值
        :param create: bool 解析记录不存在时是否自动创建，
            若解析记录自动创建，该参数需指定创建解析记录的参数
        :param kwargs: Api类公共参数
        """
        super().__init__(domain, **kwargs)
        self.domain = domain
        self.__record = {}
        self.record_list(self.domain, **kwargs)
        self.records = self.get_record_info(self.domain, **record)
        l = len(self.records)
        if l == 0:
            if create and type(create) == dict:
                logger.info('')
                create.update(self.convert_record_kwargs(record))
                self.record_create(self.domain, **create)
                self.records = self.get_record_info(self.domain, **record)
                self.record = self.records[0]
            else:
                logger.critical('查询记录为{}的解析记录不存在'.format(record))
                raise TypeError('指定值的解析记录不存在，且未在create指定创建记录参数')
        elif l == 1:
            self.record = self.records[0]
        else:
            logger.info('查询条件匹配多个记录,{},默认匹配第一个'.format(self.records))
            # 这边可修改为询问
            self.record = self.records[0]
        if interval < 1:
            self.interval = self.record['ttl']
        else:
            self.interval = interval

    @property
    def record(self):
        return self.__record
        
    @record.setter
    def record(self, info):
        """record.
        修改记录值时，修改对应的二级域名等信息
        :param info:
        """
        if info not in self.records:
            logger.warn('该记录在records里不存在，请先在records添加该记录')
            return False
        self.subDomain = info['name']
        self.addr = '.'.join([self.subDomain, self.domain])
        self.id = info['id']
        self.__record = info

    def __ddns_delete(self, ip):
        """__ddns_delete.
        以新建及删除的方式进行动态域名解析
        :param ip: 本地ip
        """
        info = self.record
        kwargs = self.get_origin_kwargs(info)
        kwargs['value'] = ip
        data = self.record_create(self.domain, **kwargs)
        self.record_delete(domain, info['id'])
        self.records.remove(info)
        new_id = data['record']['id']
        info = self.get_record_info(self.domain, id=new_id)[0]
        self.records.append(info)
        self.record = info

    def __ddns_modify(self, ip):
        """__ddns_modify.
        以修改记录的方式进行动态域名解析
        生效时间会受到ttl值影响
        :param ip: 本地ip 
        """
        info = self.record
        kwargs = self.get_origin_kwargs(info)
        kwargs['value'] = ip
        self.record_modify(self.domain, **kwargs)

    def diff_check(self, **kwargs):
        """diff_check.
        判断通过addr能否解析到本地ip
        :return 无法解析到本地ip时，返回本地ip
        """
        ip = get_host_ip(**kwargs)
        if ip not in self.get_rm_ip():
            return ip

    def dnspod_AAAA(self):
        """dnspod_AAAA. 修改AAAA记录"""
        ip = self.diff_check()
        if ip:
            return self.record_modify(self.domain, self.subDomain, value=ip)

    def get_rm_ip(self):
        """get_rm_ip. 解析addr"""
        return get_addr_ip(self.addr, 80)
    
    def run(self, modify=True, diff_check='', **kwargs):
        """run 开始动态域名解析
        :param modify: fn ip变化时的函数
        :param diff_check: fn 判断ip是否变化函数，并返回变化值
        :param kwargs:
            interval int 检测ip变化时间间隔 默认在初始化时指定
            unblock bool 非阻塞启动
            get_fn_only 返回动态解析函数
        """
        if not callable(modify):
            if modify:
                record_operate = self.__ddns_modify
            else:
                record_operate = self.__ddns_delete
        else:
            record_operate = modify

        if not callable(diff_check):
            diff_check = self.diff_check

        interval = kwargs.get('interval') or self.interval
        
        def ddns():
            ip = diff_check()
            if ip:
                record_operate(ip=ip)
            else:
                logger.debug('解析记录值未改变')

        if kwargs.get('get_fn_only'):
            return ddns
    
        def __main():
            logger.info('开始动态域名解析')
            while 1:
                try:
                    ddns()
                    sleep(interval)
                except KeyboardInterrupt:
                    logger.info("Exit for user interrupt")
                    sys.exit()
                except OSError:
                    r = ip_check()
                    if r == False:
                        while 1:
                            logger.warn('无网络连接，{}秒后重试'.format(interval))
                            sleep(interval)
                    elif r == True:
                        raise

                    else:
                        logger.info('网络检测结果：{}'.format(r))
                        logger.warn('当前网络不符合动态域名解析要求')

                except Exception as e:
                    logger.critical("发生错误{}，程序结束运行".format(e))
                    sys.exit()

        if kwargs.get("unblock"):
            Thread(target=__main).start()
        else:
            __main()


def ip_check():
    logger.debug('测试开始')
    logger.debug('正在检测网络环境')
    ipv4 = get_host_ip(socket.AF_INET, '119.29.29.29', check=False)
    ipv6 = get_host_ip(check=False)
    if not (ipv4 or ipv6):
        logger.warn('联网失败，请检查网络连接')
        return False
    else:
        if ipv4 and ipv6:
            logger.info('ipv4：{}\nipv6：{}\n'.format(ipv4, ipv6))
            logger.info('当前同时支持ipv4与ipv6')
            return True
        else:
            params = ('ipv4', ipv4) if ipv4 else ('ipv6', ipv6)
            logger.info('当前仅支持{}：'.format(*params))
            return params
    # for addr in ['baidu.com', 'google.com']:
    #     ips = get_addr_ip(addr)
    #     logger.debug('{} 解析ip：{}'.format(addr, ips))


def main():
    basicConfig(level=10)
    ip_check()
    ddns = DDns('baidu.com', {'value': 'ipv6', 'type': 'AAAA'},
            secretId='AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhESA',
            secretKey='Gu5t9xGARNpq86cd98joQYCN3Cozk1qA')
    
if __name__ == '__main__':
    main()

