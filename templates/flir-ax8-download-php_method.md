# FLIR-AX8 download.php 任意文件下载

## 漏洞描述
FLIR-AX8 download.php文件过滤不全 存在任意文件下载漏洞

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![image-20220913103521047](images/202209131035126.png)

出现漏洞的文件为 **download.php**

```php
<?php
/**
 * Copyright 2012 Armand Niculescu - MediaDivision.com

## Payloads
```
简单审计可以发现 file参数 为可控参数且没有过滤参数，导致可以下载任意文件
```
