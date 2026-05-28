# PHPStudy 后台管理页面 one click RCE

## 漏洞描述
phpStudy 集安全、高效、功能与一体，已获得全球用户认可安装，运维也高效。支持一键 LAMP、LNMP、集群、监控、网站、数据库、FTP、软件中心、伪静态、云备份、SSL、多版本共存、Nginx 反向代理、服务器防火墙、Web 防火墙、监控大屏等服务器管理功能。phpStudy 面板存在存储型 XSS 漏洞，攻击者可以通过 js 调用面板中的计划任务执行系统命令。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
### 方式 1 SQL 注入

phpstudy 访问面板登录页面需要添加如下 Headers：

```
x-requested-with: XMLHttpRequest
```

![image-20230519091358703](images/image-20230519091358703.png)


## Payloads
```
x-requested-with: XMLHttpRequest
```
```
填写 Payload，验证码处需要正确输入：
```
