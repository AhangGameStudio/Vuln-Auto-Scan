# IceWarp WebClient basic 远程命令执行漏洞

## 漏洞描述
IceWarp WebClient 存在远程命令执行漏洞，攻击者构造特殊的请求即可远程命令执行

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202101850566.png)



漏洞请求包为

```plain
POST /webmail/basic/ HTTP/1.1
