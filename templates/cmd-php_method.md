# 博华网龙防火墙 cmd.php 远程命令执行漏洞

## 漏洞描述
博华网龙防火墙 cmd.php 过滤不足，导致命令拼接执行远程命令

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![img](images/202202162249275.png)

存在漏洞的文件为 **/diagnostics/cmd.php**

```php
<?php
    include_once("pub/pub.inc");
    include_once("pub/session.inc");

## Payloads
```
可以发现其中存在多个命令执行点，均可进行命令拼接执行恶意命令

构造命令执行
```
