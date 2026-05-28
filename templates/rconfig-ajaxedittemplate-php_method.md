# rConfig ajaxEditTemplate.php 后台远程命令执行漏洞

## 漏洞描述
rConfig ajaxEditTemplate.php 存在后台远程命令执行

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
漏洞文件为 **rconfig/www/lib/ajaxHandlers/ajaxEditTemplate.php**

```php
<?php
require_once("/home/rconfig/classes/usersession.class.php");
require_once("/home/rconfig/classes/ADLog.class.php");
require_once("/home/rconfig/classes/spyc.class.php");
require_once("/home/rconfig/config/functions.inc.php");

$log = ADLog::getInstance();

## Payloads
```
关键代码如下
```
```
$fileName -->  $fullpath ---> 写入文件，其中 fileName参数 POST传入时没有过滤导致目录可上传任意位置
```
```
![](images/202202162243099.png)
```
```
POST code 传参写入文件 test.php.yml, 请求包如下
```
