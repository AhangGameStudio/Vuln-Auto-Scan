# 锐捷 EG易网关 管理员账号密码泄露漏洞

## 漏洞描述
锐捷EG易网关 login.php存在 CLI命令注入，导致管理员账号密码泄露漏洞

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202110926402.png)

漏洞文件 login.php

```php
<?php

/**

## Payloads
```
关键代码部分
```
```
发送请求包，拼接 CLI指令 **show webmaster user**
```
