# **腾讯Api的CNS模块补充**
## **简介**
腾讯云产品有提供支持多种语言的官方的SDK文档，也包括python，但是对于cns模块支持有限，目前（2020-6-3）并没有现成的python模块来操作腾讯云的域名管理。根据官方api文档，使用python访问腾讯云的cns资源，并实现ipv6动态域名解析功能。
## **安装**
- pip工具安装
```
pip install tencentApi        
```                                              
- 源码安装
``` 
git clone https://github.com/shenchucheng/tencentapi.git tencentapi
cd tencentapi
python3 setup.py sdist bdist_wheel
python3 -m pip install dist/tencentApi*.tar.gz 
```

## **cli工具**
安装完成后可使用cns工具行命令
```
cns --help  # 显示帮助信息
cns config  # 进行ip环境检测
cns ddns run <flags>  
cns profile ~/.cnsrc  # 生成动态域名解析json文件
cns ddns run --profile ~/.cnsrc  # 以配置文件的方式启动 !!!注意补充配置文件的信息
```
