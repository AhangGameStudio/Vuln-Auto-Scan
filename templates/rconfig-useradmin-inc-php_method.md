# rConfig useradmin.inc.php 信息泄露漏洞

## 漏洞描述
rConfig useradmin.inc.php 存在信息泄露漏洞，通过访问文件获取用户邮箱信息和登录名

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
出现漏洞的文件

```php
<?php
/* Includes */
require_once("../classes/db2.class.php");
include_once('../classes/paginator.class.php');

/* Instantiate DB Class */
$db2 = new db2();

## Payloads
```
文件没有设定权限，任何人可以访问泄露信息

漏洞验证的Url为
```
