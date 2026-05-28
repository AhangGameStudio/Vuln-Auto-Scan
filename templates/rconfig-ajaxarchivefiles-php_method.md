# rConfig ajaxArchiveFiles.php 后台远程命令执行漏洞

## 漏洞描述
rConfig ajaxArchiveFiles.php文件中由于对path参数和ext参数进行命令拼接，导致攻击者可以远程命令执行获取服务器权限

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
存在漏洞的文件

**/home/rconfig/www/lib/ajaxHandlers/ajaxArchiveFiles.php**

```php
<?php
require_once("/home/rconfig/classes/usersession.class.php");
require_once("/home/rconfig/classes/ADLog.class.php");
require_once("/home/rconfig/config/functions.inc.php");
$log = ADLog::getInstance();

## Payloads
```
关键代码如下
```
```
![img](https://g.yuque.com/gr/latex?mainPath参数和)**ext参数** 用户可控
```
```
没有使用过滤直接拼接命令，导致命令执行，并因为sudo而root权限执行，由于是后台漏洞所以需要登录，配合任意用户创建可以RCE

请求包为
```
