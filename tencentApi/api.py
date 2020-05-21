#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# File Name: api.py
# Author: Shechucheng
# Created Time: 2020-05-18 21:35:12

"""
## **腾讯云api签名算法**
** 官方文档链接 **：
- [签名算法](https://cloud.tencent.com/document/api/213/30654)
- [腾讯云API密钥管理](https://console.cloud.tencent.com/cam/capi)
- [腾讯云官方sdk(python)文档](https://cloud.tencent.com/document/sdk/Python)
- [sdk简介——支持的产品列表](https://cloud.tencent.com/document/product/494/42698)
腾讯云api访问请求参数包含secretId与secretKey，需先在腾讯云API密钥管理中创建。
腾讯云官方有sdk的python包，但是没有支持所有的产品，比如cns模块域名管理；
对于官方未支持的功能可据此补充并定制功能

@class Api 所有腾讯云Api对象基类 在此实现访求请求的签名算法
@class CnsApi 域名解析类 对域名进行增删改操作
注：实例化以上实例均需要secretId与secretKey

"""
import base64
import hashlib
import hmac
import json
import os
import random
import time
import requests

from logging import getLogger


logger = getLogger('tencentapi')


class Api:
    def __init__(self, secretId, secretKey, module):
        """
        实例化api对象，构造访问域名
        secretId与secretKey的获取最好使用子账户进行管理
        :param secretId: string
        :param secretKey: string
        :param module: 对应的操作资源，例如cns cdn
        """
        self.secretId = secretId
        self.secretKey = secretKey
        self.key = self.secretKey.encode(encoding='utf-8')
        self.module = module
        self.sorted = lambda x: x[0]

    @property
    def module(self):
        return self.__module

    @module.setter
    def module(self, module):
        """module.
        构造访问链接，并跟随module名改变
        :param module:
        """
        self.__module = module
        self.base_url = '{0}.api.qcloud.com/v2/index.php?'.format(module)
        self.https_url = 'https://' + self.base_url

    def sign(self, method='GET', **kwargs):
        """sign.
        [腾讯云api签名算法v1](https://cloud.tencent.com/document/api/213/15693)
        [官方签名算法实现](https://github.com/TencentCloud/tencentcloud-sdk-python/blob/master/QcloudApi/common/sign.py)
        :param kwargs:
        """
        sign_method = kwargs.get('SignatureMethod', 'HmacSHA256')
        if sign_method == 'HmacSHA256':
            digestmod = hashlib.sha256
        else:
            digestmod = hashlib.sha1
        params = sorted(kwargs.items(), key=self.sorted)
        src = method + self.base_url
        src += '&'.join("{}={}".format(*i) for i in params)
        logger.debug(src)
        src = src.encode(encoding='utf-8')
        sign = hmac.new(self.key, src, digestmod=digestmod).digest()
        return base64.b64encode(sign).decode('utf-8')

    def get(self, action,  **kwargs):
        """get.
        发起get请求
        :param action: 接口功能
        :param kwargs: 对应模块请求参数
        """
        config = {
            'Action': action,
            'Nonce': random.randint(10000, 99999),
            'SecretId': self.secretId,
            'SignatureMethod': 'HmacSHA256',
            'Timestamp': int(time.time()),
        }
        config.update(kwargs)
        config['Signature'] = self.sign(**config)
        r = requests.get(self.https_url, params=config).json()
        if r.get('code')  == 0:
            return r
        else:
            # 当返回值的'code'不为0时，则资源访问失败
            # 此时，返回值的'codeDesc'描述了错误类型，'message'为错误内容
            # 可在此处进行处理
            raise Exception(r)


class CnsApi(Api):
    """
    腾讯云解析记录相关接口:
    https://cloud.tencent.com/document/product/302/3875
    接口请求域名：cns.api.qcloud.com
    腾讯云当前并未对cns模块进行支持
    密钥管理虽然建议使用子账户，但是当前腾讯云并不支持cns配置权限
    """

    def __init__(self, *domain, **kwargs):
        """__init__.

        :param domain: string 指定域名 
        :param kwargs: 父类Api所需参数
        """
        super().__init__(module='cns', **kwargs)
        self.__domains_info = {}
        self.__records_info = {}
        self.map = {
                'recordId': 'id',
                'subDomain': 'name', 
                'recordType': 'type',  
                'recordLine': 'line',
                }
        self.convert_record_kwargs = lambda x: {
                (self.map.get(k) or k) : v for k, v in x.items()
                }
        self.domains = domain
        if domain:
            self.domain = domain[0]
    
    @property
    def domains_info():
        return self.__domains_info

    @property
    def records_info():
        return self.__records_info

    def domain_list(self, **kwargs):
        """domain_list.
        获取用户下域名列表
        api链接：https://cloud.tencent.com/document/api/302/8505
        :param kwargs:
            包含offset length keyword qProjectId
        :return dict 请求域名信息
        """
        data = self.get(action='DomainList', **kwargs)['data']
        logger.debug('请求成功，域名信息：{}'.format(data['info']))
        for domain in data['domains']:
            self.__domains_info[domain['name']] = domain
        return data
    
    def domain_create(self, domain, **kwargs):
        """domain_create.
        新建域名 
        api链接：https://cloud.tencent.com/document/api/302/8504
        :param domain: str 域名名称
        :param kwargs: qProjectId 未指定时，默认值0
        :return dict 新建域名信息
        """
        data = self.get(action='DomainCreate', domain=domain, **kwargs)['data']
        logger.debug('请求成功，新建域名{}'.format(domain))
        domain = data['domain']
        self.__domains_info[domain['domain']] = domain
        return data

    def set_domain_status(self, domain, status):
        """set_domain_status.
        设置域名状态
        api链接：https://cloud.tencent.com/document/api/302/8508
        :param domain: str 域名名称
        :param status: str 设置状态 disable/enable
        """
        if status not in ['disable', 'enable']:
            if status:
                status = 'enable'
            else:
                status = 'disable'
        self.get(action='SetDomainStatus', domain=domain, status=status)
        logger.debug('请求成功，域名{}的当前状态为{}'.format(domain, status))
        __domain = self.__domains_info.get(domain, {})
        __domain['status'] = status
        self.__domains_info[domain] = __domain
        return True
    
    def domain_delete(self, domain):
        """domain_delete.
        删除域名
        api接口：https://cloud.tencent.com/document/api/302/3873
        :param domain: str 域名
        """
        self.get(action='DomainDelete', domain=domain)
        logger.debug('请求成功，删除域名{}'.format(domain))
        return self.__domains_info.pop(domain, {'domain': domain})

    def record_list(self, domain='', **kwargs):
        """record_list
        获取域名解析列表
        api接口：https://cloud.tencent.com/document/api/302/8517
        :param domain: str 域名 不指定则为self.domain或者随机某个域名
        :param kwargs:
            offset length subDomain recordType qProjectId
        :return: dict 请求接口返回值，解析记录列表
        """
        domain = domain or self.domain or self.__domains_info.keys()[0]
        data = self.get(action='RecordList', domain=domain, **kwargs)['data']
        logger.debug('请求成功，获取域名解析记录数信息：{}'.format(data['info']))
        __domain = self.__domains_info.get(domain, {})
        __domain.update(data['domain'])
        self.__domains_info[domain] = __domain
        __records = self.__records_info.get(domain, {})
        ids = __records.keys()
        for record in data['records']:
            i = record['id']
            item =__records.get(record['id'], {})
            item.update(record)
            __records[i] = item
        self.__records_info[domain] = __records
        return data
    
    def record_create(self, domain, subDomain, recordType='A', 
            value='127.0.0.1', recordLine='默认', **kwargs):
        """record_create
        增加解析记录
        api接口：https://cloud.tencent.com/document/api/302/8516
        :param domain: str 要操作的域名（主域名，不包括 www，例如：qcloud.com）
        :param subDomain: str 子域名，例如：www
        :param value: str 记录值
        :param recordType: str 记录类型，A/CNAME/MX/TXT/NS/AAAA/SRV
        :param recordLine: str 记录的线路名称，例如："默认"
        :param kwargs:
            ttl int TTL 值，范围1 - 604800，不同等级域名最小值不同，默认为 600
            mx	int	MX 优先级，范围为0 ~ 50，当 recordType 选择 MX 时，mx 参数必选
        :return: dict 返回新增解析记录信息
        """
        kwargs.update({
            'subDomain': subDomain,
            'value': value,
            'recordLine': recordLine,
            'recordType': recordType
            }) 
        data = self.get(action='RecordCreate', domain=domain, **kwargs)['data']
        logger.debug('请求成功，新建解析记录{}'.format(data))
        record = self.convert_record_kwargs(kwargs)
        record.update(data['record'])
        __records = self.__records_info.get(domain, {})
        __records[record['id']] = record
        self.__records_info[domain] = __records
        return data

    def record_modify(self, domain, recordId, **kwargs):
        """record_modify
        修改解析记录
        api接口：https://cloud.tencent.com/document/api/302/8511
        通过domain与recordId定位解析记录修改信息
        :param domain: str 要操作的域名（主域名，不包括 www，例如：qcloud.com）
        :param recordId: int 解析记录的 ID，可通过 RecordList 接口返回值中的 ID 获取
        :param kwargs:
            参考self.record_create.__doc__
            subDomain, recordType, value, recordLine, ttl mx
        """
        kwargs['recordId'] = recordId
        data = self.get(action='RecordModify', domain=domain, **kwargs)["data"]
        logger.debug('请求成功，修改{} id为{}的解析记录'.format(domain,
            recordId))
        __records = self.__records_info.get(domain, {})
        record = __records.get(recordId, {})
        record.update(self.convert_record_kwargs(kwargs))
        __records[recordId] = record
        self.__records_info[domain] = __records
        return True

    def record_delete(self, domain, recordId):
        """record_delete.
        删除解析记录
        api接口：https://cloud.tencent.com/document/api/302/8514
        :param domain: str 要删除的解析记录域名
        :param recordId: int 要删除的解析记录id
        """
        self.get(action='RecordDelete', domain=domain, recordId=recordId)
        logger.debug('请求成功，删除{} id为{}的解析记录'.format(domain, recordId))
        self.__records_info.get(domain, {}).pop(recordId, {})
        return True

    def set_record_status(self, domain, recordId, status):
        """set_record_status.
        设置解析状态
        api接口：https://cloud.tencent.com/document/api/302/8519
        :param domain: str 修改解析记录的域名
        :param recordId: int 解析记录id
        :param status: 设置状态 enable/disable
        """
        if status not in ['enable', 'disable']:
            if status:
                status = 'enable'
            else:
                status = 'disable'
        self.get(action='RecordStatus', domain=domain,
                recordId=recordId, status=status)
        records = self.__records_info.get(domain, {})
        record = records.get(recordId, {})
        record['status'] = status
        records[recordId] = record
        self.__records_info[domain] = records
        return True

    def querry_record(self, domain, **kwargs):
        """__get_record_info.
        根据搜索条件从缓存数据中匹配记录
        :param domain: str 搜索域名
        :param kwargs: 搜索条件
        """
        records = self.__records_info.get(domain, {}).copy()
        keys = kwargs.keys()
        for record in records.values():
            if {k: record[k] for k in keys} == kwargs:
                yield record

    def get_record_info(self, domain, **kwargs):
        """get_record_info.
        获取指定条件解析记录查询的信息
        :param domain: str 搜索域名
        :param fetchone: bool 返回值个数
        :param kwargs: 查询条件
        :return 返回查询列表
        """
        return list(self.querry_record(domain, **kwargs))

    def get_record_id(self, domain, **kwargs):
        info =  self.get_record_info(domain, **kwargs)
        return list(map(lambda x: x['id'], info))


def main():
    """main.
    对签名函数等进行验证：
    签名函数验证api：https://cloud.tencent.com/document/product/215/1693
    """
    api = Api(module='cvm', secretId='AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhESA',
            secretKey='Gu5t9xGARNpq86cd98joQYCN3Cozk1qA')
    kwargs = {
            'Action' : 'DescribeInstances',
            'InstanceIds.0' : 'ins-09dx96dg',
            'Nonce' : '11886',
            'Region' : 'ap-guangzhou',
            'SecretId' : 'AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhESA',
            'SignatureMethod' : 'HmacSHA256',
            'Timestamp' : '1465185768'
            }
    sign = api.sign(**kwargs)
    sign_official = '0EEm/HtGRr/VJXTAD9tYMth1Bzm3lLHz5RCDv1GdM8s='
    print('官网签名结果：{}，sign函数验证签名结果：{}，一致性：{}'.format(
            sign_official, sign, sign_official == sign
        ))

if __name__ == '__main__':
    main()

