# 锐捷 SSL VPN 越权访问漏洞

## 漏洞描述
Ruijie SSL VPN 存在越权访问漏洞，攻击者在已知用户名的情况下，可以对账号进行修改密码和绑定手机的操作。并在未授权的情况下查看服务器资源

参考阅读：

- https://mp.weixin.qq.com/s?__biz=MzU1NTkzMTYxOQ==&mid=2247484601&idx=1&sn=d6d6f4496243d98e688667faff137973

## 危害等级
HIGH

## 参考链接
- https://mp.weixin.qq.com/s?__biz=MzU1NTkzMTYxOQ==&mid=2247484601&idx=1&sn=d6d6f4496243d98e688667faff137973

## 漏洞复现方法
访问目标 http://xxx.xxx.xxx.xxx/cgi-bin/installjava.cgi



![](images/202202110919224.png)

POC请求包如下

```plain
GET /cgi-bin/main.cgi?oper=getrsc HTTP/1.1

## Payloads
```
其中注意的参数为
```
