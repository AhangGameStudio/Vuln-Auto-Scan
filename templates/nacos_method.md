# Nacos 未授权访问漏洞

## 漏洞描述
2020年12月29日，Nacos官方在github发布的issue中披露Alibaba Nacos 存在一个由于不当处理User-Agent导致的未授权访问漏洞 。通过该漏洞，攻击者可以进行任意操作，包括创建新用户并进行登录后操作。

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
可以再项目的 issues 中看到大量的关于越权的安全问题的讨论



https://github.com/alibaba/nacos/issues/1105



![](images/202202102003894.png)


## Payloads
```
同样的我们简化请求
```
```
![](images/202202102004662.png)

![](images/202202102004665.png)



看到有文章说要加上**User-Agent请求头**
```
