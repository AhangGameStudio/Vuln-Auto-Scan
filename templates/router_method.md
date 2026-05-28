# 奇安信网康 下一代防火墙 router 远程命令执行漏洞

## 漏洞描述
奇安信 网康下一代防火墙存在远程命令执行，通过漏洞攻击者可以获取服务器权限

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202162229920.png)

发送如下请求包

```plain
![](C:\Users\47236\Desktop\2.png)POST /directdata/direct/router HTTP/1.1
Host: XXX.XXX.XXX.XXX
Connection: close

## Payloads
```
再请求获取命令执行结果
```
