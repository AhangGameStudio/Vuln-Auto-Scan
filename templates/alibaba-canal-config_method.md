# Alibaba Canal config 云密钥信息泄露漏洞

## 漏洞描述
由于/api/v1/canal/config  未进行权限验证可直接访问，导致账户密码、accessKey、secretKey等一系列敏感信息泄露

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
验证漏洞的Url为

```plain
/api/v1/canal/config/1/0
```

![](images/202202102002400.png)



