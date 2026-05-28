# 金山 V8 终端安全系统 downfile.php 任意文件读取漏洞

## 漏洞描述
金山 V8 终端安全系统 存在任意文件读取漏洞，攻击者可以通过漏洞下载服务器任意文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
存在漏洞的文件 **/Console/htmltopdf/downfile.php**



```php
<?php	
			$filename= $_GET["filename"];
            
			$filename=iconv("UTF-8","GBK//IGNORE", $filename);


## Payloads
```
文件中没有任何的过滤 通过filename参数即可下载任意文件



POC为
```
