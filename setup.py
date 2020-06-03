#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# File Name: setup.py
# Author: Shechucheng
# Created Time: 2020-06-03 19:30:28

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="tencentApi",
    version="0.1.0",
    author="shenchucheng",
    author_email="shenchucheng@126.com",
    description="腾讯云资源api，补充cns模块的api函数，实现动态域名解析。",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shenchucheng/tencentapi",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires = [
        'fire>=0.3.1',
        'requests>=2.23.0'
        ],
    entry_points = {
        'console_scripts': [
            'cns=tencentApi.cli.app:main',
            ]
        }

)

def main():
    pass


if __name__ == "__main__":
    main()
     
