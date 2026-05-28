# 腾达路由器 D151/D31未经身份验证的配置下载

## 漏洞描述
攻击者可利用此漏洞，通过请求{IP}/goform/getimage即可下载当前路由器配置（包括管理员登录名），也可以通过请求激活telnet服务/goform/telnet（默认情况下该服务已启用）。

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
poc：

```python
import struct
import itertools
import random, sys
import requests
import base64


