# JumpServer 远程命令执行漏洞

## 漏洞描述
JumpServer 是全球首款完全开源的堡垒机, 使用GNU GPL v2.0 开源协议, 是符合4A 的专业运维审计系统。 JumpServer 使用Python / Django 进行开发。2021年1月15日，阿里云应急响应中心监控到开源堡垒机JumpServer发布更新，修复了一处远程命令执行漏洞。由于 JumpServer 某些接口未做授权限制，攻击者可构造恶意请求获取敏感信息，或者执行相关操作控制其中所有机器，执行任意命令。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
详情参考：https://www.o2oxy.cn/2921.html

poc.py：

```python
# -*- coding: utf-8 -*-
# import requests
# import json
# data={"user":"4320ce47-e0e0-4b86-adb1-675ca611ea0c","asset":"ccb9c6d7-6221-445e-9fcc-b30c95162825","system_user":"79655e4e-1741-46af-a793-fff394540a52"}
#
