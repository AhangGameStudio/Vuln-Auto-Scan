# 百卓 Smart importhtml.php 远程命令执行漏洞

## 漏洞描述
百卓 importhtml.php文件sql语句无过滤，通过Sql语句可远程命令执行

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![](images/202202140918333.png)

出现漏洞的文件 **importhtml.php**

```php
<?php 
include_once("global.func.php");
if($_SESSION['language']!="english")

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
