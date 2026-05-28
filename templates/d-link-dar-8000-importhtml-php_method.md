# D-Link DAR-8000 importhtml.php 远程命令执行漏洞

## 漏洞描述
D-Link DAR-8000 importhtml.php文件存在SQL注入导致 远程命令执行漏洞

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面



![](images/202202162227588.png)



出现漏洞的文件 **importhtml.php**


## Payloads
```
跟踪exportHtmlMail函数
```
```
这里可以发现通过base64解码后执行的Sql语句结果传入函数exportHtmlMail中调用system执行, 而 $post_filename 可控
```
```
验证POC
```
