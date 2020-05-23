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

