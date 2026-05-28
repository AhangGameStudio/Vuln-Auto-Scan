# 锐捷 EG易网关 download.php 任意文件读取漏洞

## 漏洞描述
锐捷EG易网关 download.php 存在后台任意文件读取漏洞，导致可以读取服务器任意文件

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
首先登录到后台中(可以组合 锐捷EG易网关 管理员账号密码泄露漏洞)

漏洞文件 download.php

```php
<?php
/**
 * 文件下载
 */
define('IN', true);     //定位该文件是入口文件

## Payloads
```
关键代码为
```
```
直接从Get请求中提取 file参数读取文件，可以使用 **../** 跳转目录

验证POC
```
